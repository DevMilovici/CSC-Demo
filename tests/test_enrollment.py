"""Sign-up with email confirmation, the OAuth 2.0 credential-creation flow and credentials/create."""

import base64
import email
import hashlib
import json
import re
import secrets
import socket
import sys
from email import policy
from pathlib import Path
from urllib.parse import parse_qs, urlencode, urlparse

import pytest
from aiosmtpd.controller import Controller
from cryptography import x509
from cryptography.x509.oid import ExtensionOID, NameOID
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "server"))
import csc_server  # noqa: E402
import pki  # noqa: E402

B = "/csc/v2"
CLIENT_ID, SECRET = "csc-signer", "csc-signer-demo-secret"
REDIRECT = "http://127.0.0.1:8000/oauth/callback"
QES, ADV = "0.4.0.194112.1.2", "0.4.0.2042.1.1"
RAR_TYPE = "https://cloudsignatureconsortium.org/2025/credential-creation"


class Inbox:
    def __init__(self):
        self.messages = []

    async def handle_DATA(self, server, session, envelope):
        self.messages.append(email.message_from_bytes(envelope.content, policy=policy.default))
        return "250 OK"

    def text(self, i=-1):
        return self.messages[i].get_body(preferencelist=("plain",)).get_content()


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
    monkeypatch.delenv("SMTP_USERNAME", raising=False)
    monkeypatch.delenv("SMTP_PASSWORD", raising=False)
    yield box
    ctl.stop()


@pytest.fixture()
def c(inbox, monkeypatch, tmp_path):
    monkeypatch.setattr(pki, "DATA_DIR", tmp_path)  # keys of created credentials go to a temp dir
    csc_server.STATE = csc_server.build_state()
    return TestClient(csc_server.app)


# --------------------------------------------------------------------------- helpers
def signup(c, mail="bob@example.com", password="correct horse battery", given="Bob", family="Builder", **extra):
    return c.post("/account/signup", data={"given_name": given, "family_name": family, "email": mail,
                                           "password": password, "password2": extra.get("password2", password),
                                           "next": extra.get("next", "")})


def confirm_link(inbox):
    return re.search(r"(http\S+/account/verify\?token=\S+)", inbox.text()).group(1)


def register(c, inbox, mail="bob@example.com", password="correct horse battery"):
    assert signup(c, mail, password).status_code == 200
    assert c.get(confirm_link(inbox)).status_code == 200


def basic(user, password):
    return {"Authorization": "Basic " + base64.b64encode(f"{user}:{password}".encode()).decode()}


def pkce():
    verifier = secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    return verifier, challenge


def rar(policy_oid=QES):
    return json.dumps([{"type": RAR_TYPE, "credentialCreationRequest": {
        "certificatePolicy": policy_oid, "subjectData": {"given_name": "Mallory", "family_name": "Fake"}}}])


def authorize_url(challenge, details=None, scope=None, state="st-123", redirect=REDIRECT, client=CLIENT_ID):
    params = {"response_type": "code", "client_id": client, "redirect_uri": redirect, "state": state,
              "code_challenge": challenge, "code_challenge_method": "S256"}
    if details:
        params["authorization_details"] = details
    if scope:
        params["scope"] = scope
    return "/oauth2/authorize?" + urlencode(params)


def txn_of(page):
    return re.search(r'name="txn" value="([^"]+)"', page).group(1)


def approve(c, url, user="bob@example.com", password="correct horse battery", pin="2468", pin2=None,
            decision="approve"):
    page = c.get(url)
    assert page.status_code == 200, page.text
    return c.post("/oauth2/authorize", follow_redirects=False, data={
        "txn": txn_of(page.text), "username": user, "password": password, "pin": pin, "pin2": pin2 or pin,
        "decision": decision})


def code_from(resp):
    assert resp.status_code == 302, resp.text
    loc = resp.headers["location"]
    assert loc.startswith(REDIRECT)
    return parse_qs(urlparse(loc).query)


def exchange(c, code, verifier, details=None, **over):
    data = {"grant_type": "authorization_code", "code": code, "redirect_uri": REDIRECT,
            "code_verifier": verifier, "client_id": CLIENT_ID, "client_secret": SECRET}
    if details:
        data["authorization_details"] = details
    data.update(over)
    return c.post("/oauth2/token", data=data)


def creation_token(c, policy_oid=QES, pin="2468"):
    verifier, challenge = pkce()
    details = rar(policy_oid)
    q = code_from(approve(c, authorize_url(challenge, details), pin=pin))
    r = exchange(c, q["code"][0], verifier, details)
    assert r.status_code == 200, r.text
    return r.json()


def create(c, token, policy_oid=QES, **extra):
    return c.post(f"{B}/credentials/create", headers={"Authorization": f"Bearer {token}"}, json={
        "credentialCreationRequest": {"certificatePolicy": policy_oid}, "credentialInfo": True,
        "certificates": "chain", "certInfo": True, **extra})


def service_token(c, user="bob@example.com", password="correct horse battery"):
    r = c.post(f"{B}/auth/login", json={}, headers=basic(user, password))
    assert r.status_code == 200, r.text
    return {"Authorization": "Bearer " + r.json()["access_token"]}


# --------------------------------------------------------------------------- info
def test_info_advertises_oauth_and_create(c):
    info = c.post(f"{B}/info", json={}).json()
    assert "oauth2code" in info["authType"] and info["oauth2"].endswith("/") and info["supportsRar"] is True
    assert "credentials/create" in info["methods"]


# --------------------------------------------------------------------------- sign-up
def test_signup_sends_confirmation_and_login_needs_it(c, inbox):
    r = signup(c)
    assert r.status_code == 200 and "Check your inbox" in r.text
    assert inbox.messages[0]["To"] == "bob@example.com"
    assert c.post(f"{B}/auth/login", json={}, headers=basic("bob@example.com", "correct horse battery")).json()[
        "error"] == "authentication_error"
    link = confirm_link(inbox)
    assert "Email confirmed" in c.get(link).text
    assert c.get(link).status_code == 400  # single use
    service_token(c)
    service_token(c, "BOB@example.com")  # usernames are case-insensitive emails


def test_signup_validation(c, inbox):
    assert "different" in signup(c, password2="something else entirely").text
    r = signup(c, password="short")
    assert r.status_code == 400 and "10 to 128 characters" in r.text
    assert signup(c, mail="not-an-email").status_code == 400
    assert signup(c, given="<script>").status_code == 400
    assert not inbox.messages


def test_signup_existing_account_and_resignup(c, inbox):
    signup(c)
    signup(c, password="another long password")  # unconfirmed: re-sign-up replaces it
    first, second = re.findall(r"token=(\S+)", inbox.text(0))[0], re.findall(r"token=(\S+)", inbox.text(1))[0]
    assert c.get(f"/account/verify?token={first}").status_code == 400  # old link no longer works
    assert c.get(f"/account/verify?token={second}").status_code == 200
    service_token(c, password="another long password")
    assert signup(c).status_code == 409


def test_signup_rate_limited_per_email(c, inbox):
    for _ in range(3):
        assert signup(c).status_code == 200
    assert signup(c).status_code == 429


def test_next_only_returns_to_authorize(c, inbox):
    signup(c, next="https://evil.example/phish")
    assert "evil" not in c.get(confirm_link(inbox)).text
    signup(c, mail="eve@example.com", next="/oauth2/authorize?client_id=csc-signer")
    assert 'href="/oauth2/authorize?client_id=csc-signer"' in c.get(confirm_link(inbox)).text


# --------------------------------------------------------------------------- OAuth + credentials/create
def test_full_rar_flow_creates_credential_from_account_data(c, inbox):
    register(c, inbox)
    verifier, challenge = pkce()
    details = rar(ADV)
    page = c.get(authorize_url(challenge, details))
    assert "Normalized certificate" in page.text and page.headers["x-frame-options"] == "DENY"
    q = code_from(approve(c, authorize_url(challenge, details), pin="2468"))
    assert q["state"] == ["st-123"]

    tok = exchange(c, q["code"][0], verifier, details).json()
    assert tok["token_type"] == "Bearer" and tok["expires_in"] == csc_server.CREATION_TOKEN_TTL
    subject = tok["authorization_details"][0]["credentialCreationRequest"]["subjectData"]
    assert subject == {"given_name": "Bob", "family_name": "Builder"}  # "Mallory Fake" from the client was replaced

    r = create(c, tok["access_token"], ADV, authData=[{"id": "PIN"}])
    assert r.status_code == 201, r.text
    info = r.json()
    assert info["SCAL"] == "1" and len(info["cert"]["certificates"]) == 2
    cert = x509.load_der_x509_certificate(base64.b64decode(info["cert"]["certificates"][0]))
    assert cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == "Bob Builder"
    policies = cert.extensions.get_extension_for_oid(ExtensionOID.CERTIFICATE_POLICIES).value
    assert policies[0].policy_identifier.dotted_string == ADV

    # the creation token was for one credential only
    assert create(c, tok["access_token"], ADV).status_code == 401

    # the new credential shows up for the user and signs with the PIN chosen on the consent page
    svc = service_token(c)
    cid = info["credentialID"]
    assert cid in c.post(f"{B}/credentials/list", json={}, headers=svc).json()["credentialIDs"]
    h = base64.b64encode(hashlib.sha256(b"doc").digest()).decode()
    sad = c.post(f"{B}/credentials/authorize", headers=svc, json={
        "credentialID": cid, "numSignatures": 1, "authData": [{"id": "PIN", "value": "2468"}]}).json()["SAD"]
    sig = c.post(f"{B}/signatures/signHash", headers=svc, json={
        "credentialID": cid, "SAD": sad, "hashes": [h], "signAlgo": csc_server.OID_SHA256_RSA})
    assert sig.status_code == 200


def test_scope_flow_without_rar(c, inbox):
    register(c, inbox)
    verifier, challenge = pkce()
    q = code_from(approve(c, authorize_url(challenge, scope="credential-creation")))
    tok = exchange(c, q["code"][0], verifier).json()
    assert "authorization_details" not in tok
    r = create(c, tok["access_token"], QES)
    assert r.status_code == 201 and r.json()["SCAL"] == "2"


def test_tokens_are_scoped(c, inbox):
    register(c, inbox)
    svc = service_token(c)
    r = c.post(f"{B}/credentials/create", headers=svc, json={"credentialCreationRequest": {"certificatePolicy": QES}})
    assert r.status_code == 403 and r.json()["error"] == "insufficient_scope"
    tok = creation_token(c)["access_token"]
    r = c.post(f"{B}/credentials/list", headers={"Authorization": f"Bearer {tok}"}, json={})
    assert r.status_code == 403


def test_create_must_match_authorized_policy(c, inbox):
    register(c, inbox)
    tok = creation_token(c, QES)["access_token"]
    r = create(c, tok, ADV)
    assert r.status_code == 403 and "authorized" in r.json()["error_description"]


def test_create_parameter_errors(c, inbox):
    register(c, inbox)
    tok = creation_token(c, QES)["access_token"]
    h = {"Authorization": f"Bearer {tok}"}
    assert c.post(f"{B}/credentials/create", headers=h, json={}).json()["error_description"] == \
        "Missing (or invalid type) parameter “credentialCreationRequest”"
    assert "certificatePolicy" in c.post(f"{B}/credentials/create", headers=h, json={
        "credentialCreationRequest": {}}).json()["error_description"]
    assert c.post(f"{B}/credentials/create", headers=h, json={
        "credentialCreationRequest": {"certificatePolicy": "1.2.3"}}).json()["error_description"] == \
        "Invalid parameter certificatePolicy"
    r = create(c, tok, QES, authData=[{"id": "PIN"}])  # SCAL 2 policy needs the email code too
    assert r.status_code == 400 and "authData" in r.json()["error_description"]
    assert create(c, tok, QES, authData=[{"id": "PIN"}, {"id": "EMAIL_OTP"}]).status_code == 201


def test_pkce_redirect_and_code_replay(c, inbox):
    register(c, inbox)
    verifier, challenge = pkce()
    details = rar()
    code = code_from(approve(c, authorize_url(challenge, details)))["code"][0]
    assert exchange(c, code, "x" * 50, details).json()["error"] == "invalid_grant"
    assert exchange(c, code, verifier, details, redirect_uri="http://127.0.0.1:8000/other").json()[
        "error"] == "invalid_grant"
    assert exchange(c, code, verifier, details, client_secret="wrong").status_code == 400
    assert exchange(c, code, verifier).json()["error_description"] == "Missing parameter authorization_details"
    first = exchange(c, code, verifier, details)
    assert first.status_code == 200
    replay = exchange(c, code, verifier, details)
    assert replay.json()["error"] == "invalid_grant"
    # replaying the code revoked the token it had produced
    assert create(c, first.json()["access_token"]).status_code == 401


def test_authorize_rejects_bad_requests(c, inbox):
    _, challenge = pkce()
    # unregistered redirect_uri: error page, never a redirect
    r = c.get(authorize_url(challenge, rar(), redirect="https://evil.example/cb"), follow_redirects=False)
    assert r.status_code == 400 and "location" not in r.headers
    r = c.get(authorize_url(challenge, rar(), client="nobody"), follow_redirects=False)
    assert r.status_code == 400
    # other errors go back to the client
    r = c.get(authorize_url("short", rar()), follow_redirects=False)
    assert "error=invalid_request" in r.headers["location"]
    r = c.get(authorize_url(challenge, scope="credential"), follow_redirects=False)
    assert "error=invalid_scope" in r.headers["location"]
    r = c.get(authorize_url(challenge, rar("1.2.3")), follow_redirects=False)
    assert "certificatePolicy" in r.headers["location"]


def test_consent_page_checks(c, inbox):
    register(c, inbox)
    signup(c, mail="new@example.com")  # not confirmed
    _, challenge = pkce()
    url = authorize_url(challenge, rar())
    assert "Wrong" in approve(c, url, password="nope nope nope").text
    assert "Confirm your email" in approve(c, url, user="new@example.com").text
    assert "4 to 8 digits" in approve(c, url, pin="12").text
    assert "different" in approve(c, url, pin="1234", pin2="4321").text
    r = approve(c, url, decision="deny")
    assert "error=access_denied" in r.headers["location"] and "state=st-123" in r.headers["location"]


def test_credential_limit_per_user(c, inbox, monkeypatch):
    monkeypatch.setattr(csc_server, "MAX_CREDENTIALS_PER_USER", 1)
    register(c, inbox)
    assert create(c, creation_token(c)["access_token"]).status_code == 201
    _, challenge = pkce()
    assert "maximum" in approve(c, authorize_url(challenge, rar())).text


def test_oauth_revoke(c, inbox):
    register(c, inbox)
    tok = creation_token(c)["access_token"]
    r = c.post("/oauth2/revoke", data={"token": tok, "client_id": CLIENT_ID, "client_secret": SECRET})
    assert r.status_code == 204
    assert create(c, tok).status_code == 401
