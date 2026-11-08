"""Unit tests for the email-OTP CSC server and the mailer."""

import base64
import email
import hashlib
import socket
import sys
from email import policy
from pathlib import Path

import pytest
from aiosmtpd.controller import Controller
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "server"))
import csc_server  # noqa: E402
import mailer  # noqa: E402

B = "/csc/v2"
H1 = hashlib.sha256(b"contract").digest()
H2 = hashlib.sha256(b"invoice").digest()
b64 = lambda d: base64.b64encode(d).decode()  # noqa: E731


class Inbox:
    def __init__(self):
        self.messages = []

    async def handle_DATA(self, server, session, envelope):
        self.messages.append(email.message_from_bytes(envelope.content, policy=policy.default))
        return "250 OK"


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture()
def inbox(monkeypatch):
    box, port = Inbox(), free_port()
    ctl = Controller(box, hostname="127.0.0.1", port=port)
    ctl.start()
    for k, v in {"SMTP_HOST": "127.0.0.1", "SMTP_PORT": str(port), "SMTP_SECURITY": "none",
                 "SMTP_FROM": "CSC Demo <signing@test>"}.items():
        monkeypatch.setenv(k, v)
    # server/.env may hold real SMTP credentials; the local test inbox has no AUTH
    monkeypatch.delenv("SMTP_USERNAME", raising=False)
    monkeypatch.delenv("SMTP_PASSWORD", raising=False)
    yield box
    ctl.stop()


@pytest.fixture()
def api(monkeypatch, tmp_path):
    monkeypatch.setenv("DEMO_USER_EMAIL", "alice@example.com")
    monkeypatch.setenv("CSC_DB_PATH", str(tmp_path / "csc.db"))  # a fresh database per test
    csc_server.STATE = csc_server.build_state()
    c = TestClient(csc_server.app)
    basic = base64.b64encode(b"alice:alice-password").decode()
    tok = c.post(f"{B}/auth/login", json={}, headers={"Authorization": f"Basic {basic}"}).json()["access_token"]
    c.headers["Authorization"] = f"Bearer {tok}"
    yield c
    csc_server.STATE.store.close()


def challenge(api, cid="cred-alice-qes"):
    return api.post(f"{B}/credentials/getChallenge", json={"credentialID": cid, "authObjectID": "EMAIL_OTP"})


def authorize(api, hashes, code=None, pin="123456"):
    auth = [{"id": "PIN", "value": pin}] + ([{"id": "EMAIL_OTP", "value": code}] if code else [])
    return api.post(f"{B}/credentials/authorize", json={
        "credentialID": "cred-alice-qes", "numSignatures": len(hashes), "hashes": [b64(h) for h in hashes],
        "hashAlgorithmOID": csc_server.OID_SHA256, "authData": auth})


def code_from(msg):
    return msg["Subject"].rsplit(" ", 1)[-1]


def test_mask():
    assert mailer.mask("alice@example.com") == "a****@example.com"
    assert mailer.mask("bo@x.org") == "b***@x.org"


def test_info_lists_getchallenge_not_sendotp():
    methods = TestClient(csc_server.app).post(f"{B}/info", json={}).json()["methods"]
    assert "credentials/getChallenge" in methods and "credentials/sendOTP" not in methods


def test_credential_info_describes_email_challenge(api):
    info = api.post(f"{B}/credentials/info", json={"credentialID": "cred-alice-qes", "authInfo": True}).json()
    obj = next(o for o in info["auth"]["objects"] if o["id"] == "EMAIL_OTP")
    assert obj["type"] == "ChallengeResponse" and "a****@example.com" in obj["description"]
    assert info["auth"]["expression"] == "PIN AND EMAIL_OTP"


def test_getchallenge_sends_real_smtp_email(api, inbox):
    assert challenge(api).status_code == 204
    assert len(inbox.messages) == 1
    msg = inbox.messages[0]
    assert msg["To"] == "alice@example.com"
    code = code_from(msg)
    assert code.isdigit() and len(code) == 6
    assert code in msg.get_body(preferencelist=("plain",)).get_content()
    assert code in msg.get_body(preferencelist=("html",)).get_content()


def test_full_flow_with_emailed_code(api, inbox):
    challenge(api)
    sad = authorize(api, [H1], code_from(inbox.messages[0])).json()["SAD"]
    r = api.post(f"{B}/signatures/signHash", json={"credentialID": "cred-alice-qes", "SAD": sad,
                                                   "hashes": [b64(H1)], "signAlgo": csc_server.OID_SHA256_RSA})
    assert r.status_code == 200 and len(r.json()["signatures"]) == 1


def test_pin_alone_is_not_enough(api, inbox):
    challenge(api)
    assert authorize(api, [H1]).json()["error"] == "invalid_authentication_data"


def test_code_is_single_use(api, inbox):
    challenge(api)
    code = code_from(inbox.messages[0])
    assert authorize(api, [H1], code).status_code == 200
    assert authorize(api, [H1], code).json()["error"] == "invalid_authentication_data"


def test_resend_cooldown_returns_429(api, inbox):
    assert challenge(api).status_code == 204
    r = challenge(api)
    assert r.status_code == 429 and "Try again" in r.json()["error_description"]


def test_smtp_failure_returns_503(api, monkeypatch):
    monkeypatch.setenv("SMTP_HOST", "127.0.0.1")
    monkeypatch.setenv("SMTP_PORT", str(free_port()))  # nothing listening
    monkeypatch.setenv("SMTP_SECURITY", "none")
    r = challenge(api)
    assert r.status_code == 503 and r.json()["error"] == "temporarily_unavailable"
    assert "cred-alice-qes" not in csc_server.STATE.otps  # no code stored if not delivered


def test_console_mode_when_smtp_not_configured(api, monkeypatch, capsys):
    monkeypatch.delenv("SMTP_HOST", raising=False)
    assert challenge(api).status_code == 204
    assert "console mode" in capsys.readouterr().out


def test_wrong_auth_object_rejected(api):
    r = api.post(f"{B}/credentials/getChallenge", json={"credentialID": "cred-alice-qes", "authObjectID": "PIN"})
    assert r.json()["error_description"] == "Invalid parameter authObjectID"


def test_scal2_hash_binding_still_enforced(api, inbox):
    challenge(api)
    sad = authorize(api, [H1], code_from(inbox.messages[0])).json()["SAD"]
    r = api.post(f"{B}/signatures/signHash", json={"credentialID": "cred-alice-qes", "SAD": sad,
                                                   "hashes": [b64(H2)], "signAlgo": csc_server.OID_SHA256_RSA})
    assert r.status_code == 400 and "not authorized" in r.json()["error_description"]
