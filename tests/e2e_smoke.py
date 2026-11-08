"""End-to-end smoke test with a real SMTP conversation (no internet needed).

Starts:
  * a local SMTP "inbox" (aiosmtpd) on 127.0.0.1:2525
  * the CSC server, configured to send its codes to that SMTP server
  * the web app
then drives the web app's API exactly like the browser does, reading the
signing code out of the delivered email.

Part 2 does the enrollment journey: sign up at the provider, confirm the email,
connect, request a new credential through the OAuth 2.0 redirect (login + PIN on
the provider's consent page), and sign a PDF with the credential that was created.

Run:  python tests/e2e_smoke.py
"""

import email
import os
import re
import subprocess
import sys
import tempfile
import time
from email import policy
from pathlib import Path

import httpx
from aiosmtpd.controller import Controller

ROOT = Path(__file__).resolve().parent.parent
CSC_PORT, WEB_PORT, SMTP_PORT = 8181, 8100, 2525


class Inbox:
    def __init__(self):
        self.messages = []

    async def handle_DATA(self, server, session, envelope):
        self.messages.append(email.message_from_bytes(envelope.content, policy=policy.default))
        return "250 OK"


def wait_for(url, timeout=20):
    t0 = time.time()
    while time.time() - t0 < timeout:
        try:
            httpx.post(url, json={}, timeout=1)
            return
        except httpx.HTTPError:
            time.sleep(0.3)
    raise RuntimeError(f"{url} did not start")


def last_code(inbox):
    return re.search(r"signing code is: (\d{6})",
                     inbox.messages[-1].get_body(preferencelist=("plain",)).get_content()).group(1)


def enrollment(inbox, pdf):
    csc_url = f"http://127.0.0.1:{CSC_PORT}"
    browser = httpx.Client(timeout=60)  # plays the user's browser at the provider
    web = httpx.Client(base_url=f"http://127.0.0.1:{WEB_PORT}", timeout=60)
    who = {"given_name": "Carol", "family_name": "Signer", "email": "carol@example.com",
           "password": "a long enough password", "password2": "a long enough password"}

    # 1. sign up and confirm the email
    r = browser.post(f"{csc_url}/account/signup", data=who)
    assert r.status_code == 200 and "Check your inbox" in r.text, r.text
    link = re.search(r"(http\S+/account/verify\?token=\S+)",
                     inbox.messages[-1].get_body(preferencelist=("plain",)).get_content()).group(1)
    assert "Email confirmed" in browser.get(link).text
    print("signed up and confirmed:", who["email"])

    # 2. connect: a brand-new account has no credentials
    r = web.post("/api/connect", json={"server": csc_url, "username": who["email"], "password": who["password"]})
    r.raise_for_status()
    assert r.json()["credentials"] == [] and r.json()["canCreate"]

    # 3. ask for a qualified credential -> redirect to the provider
    redirect = web.post("/api/credentials/request", json={"policy": "qes"}).json()["redirect"]
    assert redirect.startswith(f"{csc_url}/oauth2/authorize?") and "authorization_details" in redirect
    page = browser.get(redirect)
    txn = re.search(r'name="txn" value="([^"]+)"', page.text).group(1)
    r = browser.post(f"{csc_url}/oauth2/authorize", follow_redirects=False, data={
        "txn": txn, "username": who["email"], "password": who["password"], "pin": "135790", "pin2": "135790",
        "decision": "approve"})
    assert r.status_code == 302 and "/oauth/callback?code=" in r.headers["location"], r.text

    # 4. the provider sends the browser back to the web app, which finishes the flow
    r = web.get(r.headers["location"], follow_redirects=False)
    assert r.status_code == 303
    st = web.get("/api/state").json()
    methods = [e["method"] for e in st["log"]]
    assert methods[:3] == ["oauth2/authorize", "oauth2/token", "credentials/create"], methods
    assert st["notice"]["kind"] == "ok", st["notice"]
    cred = st["credentials"][0]
    assert cred["needsCode"] and "CN=Carol Signer" in cred["subject"]
    print("created:", cred["id"], cred["subject"], "|", st["notice"]["text"])

    # 5. sign with it: PIN chosen on the consent page + emailed code
    web.post("/api/document", files={"file": ("carol.pdf", pdf, "application/pdf")},
             data={"credentialID": cred["id"]}).raise_for_status()
    web.post("/api/challenge").raise_for_status()
    r = web.post("/api/sign", json={"pin": "135790", "code": last_code(inbox)})
    r.raise_for_status()
    v = r.json()["validation"]
    assert v["intact"] and v["valid"] and v["trusted"] and "Carol Signer" in v["signer"], v
    print("signed with the new credential ✓", v["signer"])


def main():
    inbox = Inbox()
    smtp = Controller(inbox, hostname="127.0.0.1", port=SMTP_PORT)
    smtp.start()
    data_dir = tempfile.mkdtemp()
    env = dict(os.environ, SMTP_HOST="127.0.0.1", SMTP_PORT=str(SMTP_PORT), SMTP_SECURITY="none",
               SMTP_FROM="CSC Demo <signing@csc-demo.local>", SMTP_USERNAME="", SMTP_PASSWORD="", DEMO_USER_EMAIL="alice@example.com",
               CSC_PORT=str(CSC_PORT), WEBAPP_PORT=str(WEB_PORT), CSC_SERVER=f"http://127.0.0.1:{CSC_PORT}",
               CSC_RESEND_COOLDOWN="2", PYTHONUNBUFFERED="1", WEBAPP_PUBLIC_URL=f"http://127.0.0.1:{WEB_PORT}",
               CSC_OAUTH_REDIRECT_URIS=f"http://127.0.0.1:{WEB_PORT}/oauth/callback",
               CSC_DATA_DIR=data_dir)
    procs = [
        subprocess.Popen([sys.executable, str(ROOT / "server" / "csc_server.py")], env=env),
        subprocess.Popen([sys.executable, str(ROOT / "webapp" / "app.py")], env=env),
    ]
    try:
        wait_for(f"http://127.0.0.1:{CSC_PORT}/csc/v2/info")
        wait_for(f"http://127.0.0.1:{WEB_PORT}/api/connect")
        web = httpx.Client(base_url=f"http://127.0.0.1:{WEB_PORT}", timeout=60)

        # 1. connect
        r = web.post("/api/connect", json={"server": f"http://127.0.0.1:{CSC_PORT}",
                                           "username": "alice", "password": "alice-password"})
        r.raise_for_status()
        creds = r.json()["credentials"]
        qes = next(c for c in creds if c["needsCode"])
        print("connected:", [c["id"] for c in creds], "| hint:", qes["codeHint"])

        # 2+3. upload the sample PDF for the SCAL 2 credential
        pdf = (ROOT / "webapp" / "static" / "sample-contract.pdf").read_bytes()
        r = web.post("/api/document", files={"file": ("contract.pdf", pdf, "application/pdf")},
                     data={"credentialID": qes["id"]})
        r.raise_for_status()
        print("hash to sign:", r.json()["hash"])

        # 4a. wrong code first -> rejected
        r = web.post("/api/challenge")
        r.raise_for_status()
        assert len(inbox.messages) == 1, "no email delivered"
        msg = inbox.messages[-1]
        body = msg.get_body(preferencelist=("plain",)).get_content()
        code = re.search(r"signing code is: (\d{6})", body).group(1)
        print(f"email received: To={msg['To']} Subject={msg['Subject']!r} code={code}")
        assert msg.get_body(preferencelist=("html",)) is not None, "HTML part missing"

        r = web.post("/api/sign", json={"pin": "123456", "code": "000000"})
        assert r.status_code == 400, r.text
        print("wrong code rejected:", r.json()["error"])

        # resend respects the cooldown (2 s in this test)
        assert web.post("/api/challenge").status_code == 400  # 429 from CSC -> 400 from web app
        time.sleep(2.2)
        web.post("/api/challenge").raise_for_status()
        code = re.search(r"signing code is: (\d{6})",
                         inbox.messages[-1].get_body(preferencelist=("plain",)).get_content()).group(1)

        # 4b. right PIN + code -> signed and validated
        r = web.post("/api/sign", json={"pin": "123456", "code": code})
        r.raise_for_status()
        v = r.json()["validation"]
        print("validation:", v)
        assert v["intact"] and v["valid"] and v["trusted"]
        methods = [e["method"] for e in r.json()["log"]]
        assert methods == ["credentials/authorize", "signatures/signHash"], methods

        signed = web.get("/api/download")
        assert signed.status_code == 200 and signed.content.startswith(b"%PDF")
        out = Path(tempfile.gettempdir()) / "e2e-signed.pdf"
        out.write_bytes(signed.content)
        print(f"signed PDF: {out} ({len(signed.content)} bytes)")

        # a used code cannot be replayed for a second document
        web.post("/api/document", files={"file": ("again.pdf", pdf, "application/pdf")},
                 data={"credentialID": qes["id"]}).raise_for_status()
        assert web.post("/api/sign", json={"pin": "123456", "code": code}).status_code == 400
        print("replayed code rejected ✓")

        enrollment(inbox, pdf)
        print("\nE2E OK")
    finally:
        for p in procs:
            p.terminate()
        smtp.stop()


if __name__ == "__main__":
    main()
