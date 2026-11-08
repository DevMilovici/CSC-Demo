# CSC API v2.2 demo 2: one-time codes by email, signing in a web app

Remote-signing demo for the Cloud Signature Consortium API:

```
 browser ──/api/*──▶  webapp/app.py  ──CSC API v2──▶  server/csc_server.py ──SMTP──▶ 📧 signer's inbox
 (wizard UI)          "signature application"          "remote signing service provider"
                      hashes + builds the PAdES        PIN + email code → SAD → HSM signs
```

> Demo only: software keys instead of an HSM, a self-signed CA, and in-memory state. Don't use it for real signatures.

## 1. Install

```bash
pip install -r requirements.txt
```

## 2. Configure email

```bash
cp server/.env.example server/.env
```

Edit `server/.env`:

- `DEMO_USER_EMAIL`: the inbox that should receive the codes (yours).
- The SMTP settings. **With Gmail**, turn on 2-Step Verification, create an *App Password*, and put it in `SMTP_PASSWORD`. Your normal Gmail password won't work.
  Any other provider works too: set its host, port and credentials, with `SMTP_SECURITY=ssl` for port 465 and `starttls` for 587.

If you leave `SMTP_HOST` empty, the server runs in **console mode** and prints the code instead of emailing it. That's handy for a dry run.

## 3. Run

```bash
# terminal 1: the remote signing service (CSC server) on :8080
python server/csc_server.py

# terminal 2: the web app on :8000
python webapp/app.py
```

Open **http://127.0.0.1:8000** and follow the four steps:

1. **Connect**: `info` → `auth/login` → `credentials/list` → `credentials/info` (user `alice` / `alice-password`, prefilled).
2. **Choose a credential**:
   - *Qualified signature*: SCAL 2, PIN **and** emailed code, PIN `123456`
   - *Advanced signature*: SCAL 1, PIN only, PIN `1234`
3. **Add a PDF**: drop one in, or use the sample contract. The web app hashes it locally; the provider only sees a SHA-256 hash.
4. **Approve**: **Email me a code** calls `credentials/getChallenge` and the code arrives in your inbox. Enter the PIN and the code, then `credentials/authorize` returns a SAD and `signatures/signHash` returns the signature.

The app embeds the signature as PAdES, validates it against the demo root CA and offers the signed PDF for download.
The dark panel on the right shows every CSC request and response; click an entry to see the JSON. PINs, codes, tokens and SADs are hidden.

## How the email code fits the CSC spec

`credentials/info` describes the second factor as an authentication object:

```json
{ "auth": { "mode": "explicit", "expression": "PIN AND EMAIL_OTP",
  "objects": [ { "type": "Password", "id": "PIN", "format": "N" },
               { "type": "ChallengeResponse", "id": "EMAIL_OTP", "format": "N",
                 "description": "… enter the 6 digits sent to y***@gmail.com" } ] } }
```

The client asks for the challenge, and the server emails it. The `204` response means the challenge was delivered out of band:

```
POST /csc/v2/credentials/getChallenge  {"credentialID": "cred-alice-qes", "authObjectID": "EMAIL_OTP"}
← 204 No Content
```

The user types the code. It goes to the server in-band, inside `credentials/authorize`:

```json
"authData": [ {"id": "PIN", "value": "123456"}, {"id": "EMAIL_OTP", "value": "247905"} ]
```

Rules the server enforces:

- The code is 6 digits, **single use** and expires after **5 minutes**.
- A new code can be requested at most every **30 s**; sooner returns HTTP **429**.
- SMTP failure returns **503** (`temporarily_unavailable`), and no code is stored.
- Three wrong PIN/code attempts lock the credential.
- SCAL 2 binds the SAD to the approved hash, so signing a different hash with it is rejected.

## Tests

```bash
python -m pytest -q tests          # 12 unit tests: real SMTP to a local test inbox, cooldown, 503, single use, SCAL 2
python tests/e2e_smoke.py          # full run: local SMTP inbox + server + web app, code read from the email
```

Neither test needs internet access or a real mailbox. They start a local SMTP server (`aiosmtpd`) and read the delivered message.

## Files

```
server/csc_server.py   CSC API v2.2 subset (+ getChallenge by email)
server/mailer.py       SMTP sender (text + HTML email), console fallback
server/pki.py          demo CA + credential keys (generated into server/data/)
server/.env.example    configuration template
webapp/app.py          web app backend: pyHanko interrupted signing + CSC calls + wire log
webapp/static/         index.html, app.js, style.css, sample-contract.pdf
tests/                 pytest unit tests and the end-to-end smoke test
```

## Notes and next steps

- **Security trade-offs of this demo:** HTTP on localhost, no CSRF tokens, and sessions in memory.
  Use HTTPS and a real session store before exposing it anywhere.
- **The code in the subject line** ("Your signing code: 123456") is convenient but appears in phone notifications.
  Remove it from `mailer.py` if that matters to you.
- **OAuth 2.0:** the natural next step is replacing PIN + code with an `oauth2/authorize` redirect (`scope=credential`).
  The provider then owns the login screen and the web app never sees any secret.
