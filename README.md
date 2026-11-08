# CSC API v2.2 demo 2: one-time codes by email, signing in a web app

Remote-signing demo for the Cloud Signature Consortium API:

```
 browser ──/api/*──▶  webapp/app.py  ──CSC API v2──▶  server/csc_server.py ──SMTP──▶ 📧 signer's inbox
 (wizard UI)          "signature application"          "remote signing service provider"
                      hashes + builds the PAdES        PIN + email code → SAD → HSM signs
```

Users can also **sign up** at the provider (with email confirmation) and **request their own signing
credential** through the spec's OAuth 2.0 `credential-creation` flow and `credentials/create`.

> Demo only: software keys instead of an HSM, a self-signed CA, and no real identity proofing. Don't use it for real signatures.

## 1. Install

```bash
pip install -r requirements-dev.txt     # runtime dependencies + pytest/aiosmtpd for the tests
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

### Your own account and credential

1. In step 1, follow **Create one** (it opens `http://127.0.0.1:8080/account/signup`). Enter your name, email and a password.
2. Open the confirmation link from the email (in console mode it's printed by the server).
3. Connect with your email and password. A new account has no credentials yet.
4. In step 2, pick **Qualified** or **Advanced** and press **Continue at the provider →**. On the provider's page, sign in,
   choose a 4–8 digit signing PIN and press **Approve**.
5. You land back in the web app with the new credential in the list. Sign with it as usual.

## How enrollment and credential creation fit the CSC spec

The spec covers only part of this:

| Step | In the spec? | This demo |
|---|---|---|
| Creating a user account, identity proofing | **No.** Out of scope (§1 "key creation and enrollment"; §8.2.1 "exchange and register an Account ID") | `GET/POST /account/signup` + `GET /account/verify`: email confirmation stands in for identity proofing |
| Authorizing the creation of a credential | **Yes**, §8.1.2: OAuth 2.0 only, scope `credential-creation` or RAR `authorization_details` | `oauth2/authorize` (PKCE required) → login + consent page → `oauth2/token` |
| Creating the key and certificate | **Yes**, §11.4 `credentials/create` | New RSA key + certificate from the demo CA, with the requested policy |

The flow, as seen by the web app (the "signature application"):

```
browser → GET  /oauth2/authorize?response_type=code&client_id=csc-signer&redirect_uri=…/oauth/callback
              &code_challenge=…&code_challenge_method=S256&state=…
              &authorization_details=[{"type":"https://cloudsignatureconsortium.org/2025/credential-creation",
                                       "credentialCreationRequest":{"certificatePolicy":"0.4.0.194112.1.2"}}]
        ← provider's page: user signs in, chooses the signing PIN, approves
        ← 302 …/oauth/callback?code=…&state=…
web app → POST /oauth2/token   grant_type=authorization_code, code, code_verifier, redirect_uri  (client secret via Basic)
        ← {"access_token": …, "expires_in": 300, "authorization_details": [… subjectData from the account …]}
web app → POST /csc/v2/credentials/create   Authorization: Bearer <that token>
          {"credentialCreationRequest": {"certificatePolicy": "0.4.0.194112.1.2"},
           "authData": [{"id": "PIN"}, {"id": "EMAIL_OTP"}], "credentialInfo": true, "certificates": "chain"}
        ← 201 {"credentialID": "cred-…", "cert": {…}, "SCAL": "2", …}
```

Design choices:

- **The PIN is set on the provider's consent page.** The spec gives the authorization server full control of the screen (Note 18),
  so the web app never sees the PIN.
- **The certificate name comes from the confirmed account.** Any `subjectData` the client sends is replaced, which §11.4 allows.
- **Supported policies:** `0.4.0.194112.1.2` (QCP-n-qscd, SCAL 2, PIN + email code) and `0.4.0.2042.1.1` (NCP, SCAL 1, PIN).
- **Scoped tokens.** A creation token works only for `credentials/create`, only once, and only for the policy the user approved.
  A service token from `auth/login` can't create credentials.
- **Limits:**
  - Sign-ups: 5 per IP and 3 per email address per hour.
  - Failed logins on the provider's page: 20 per IP per 10 minutes.
  - Failed `auth/login` calls: 10 per account per 10 minutes. These are counted per account because they all come
    from the signature app's single IP.
  - 5 credentials per user, 500 users. Unconfirmed accounts disappear after 24 h.

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
python -m pytest -q tests          # 38 unit tests: email codes, sign-up, OAuth (PKCE, code replay, scopes), credentials/create, persistence
python tests/e2e_smoke.py          # full run: signing as alice, then sign-up → OAuth → new credential → signing with it
```

Neither test needs internet access or a real mailbox. They start a local SMTP server (`aiosmtpd`) and read the delivered message.

## Files

```
server/csc_server.py   CSC API v2.2 subset (+ getChallenge by email), OAuth 2.0 server, sign-up
server/pages.py        provider HTML pages: sign-up, email confirmation, login + consent
server/mailer.py       SMTP sender (signing codes and confirmation links), console fallback
server/pki.py          demo CA + credential keys (generated into server/data/)
server/store.py        SQLite storage: accounts, email confirmations, credentials, refresh tokens (server/data/csc.db)
server/admin.py        operator commands: list accounts, unlock a credential, delete an account, backup, restore
server/.env.example    configuration template
webapp/app.py          web app backend: pyHanko interrupted signing + CSC calls + wire log
webapp/static/         index.html, app.js, style.css, sample-contract.pdf
tests/                 pytest unit tests and the end-to-end smoke test
Dockerfile             images for the server (--target server) and the web app (--target webapp)
compose.yaml           production stack behind the decodificat Caddy (see DEPLOY.md)
deploy/                Caddy site blocks and the update script
requirements.txt       runtime dependencies; constraints.txt pins their exact versions for the images
```

## Deploying

**With Docker:** [DEPLOY.md](DEPLOY.md) covers the production setup at csc.decodificat.ro and cscweb.decodificat.ro,
with updates, rollbacks and backups.

Without Docker, both processes read their settings from environment variables (the server also reads `server/.env`).
The defaults work on `127.0.0.1`. On a public host, put both behind an HTTPS reverse proxy and set:

| Server (`server/.env`) | Web app (environment) | |
|---|---|---|
| `CSC_PUBLIC_URL=https://csc.example.org` | `CSC_SERVER=https://csc.example.org` | where each one is reached |
| `CSC_OAUTH_REDIRECT_URIS=https://signer.example.org/oauth/callback` | `WEBAPP_PUBLIC_URL=https://signer.example.org` | must match exactly |
| `CSC_OAUTH_CLIENT_SECRET=<long random>` | `OAUTH_CLIENT_SECRET=<the same>` | the default is public in this repo |
| `CSC_HOST=0.0.0.0` | `WEBAPP_HOST=0.0.0.0` | listen address |
| `CSC_DATA_DIR=/var/lib/csc-demo` | | keys, certificates and the database (`csc.db`) |
| `DEMO_USER_PASSWORD=<your own>` | `WEBAPP_DEMO_LOGIN=` (empty) | the defaults are public; empty = no prefilled login |
| | `CSC_SERVER_LOCKED=1` | only talk to `CSC_SERVER`, ignore the URL typed in step 1 |

**Lock the web app to one server on a public host.** Without `CSC_SERVER_LOCKED`, its backend sends a request to any
URL a visitor types and shows the response. That lets visitors reach internal services on your network.

Both servers trust `X-Forwarded-For` / `X-Forwarded-Proto` only from `127.0.0.1` (uvicorn's default; change it with
`FORWARDED_ALLOW_IPS`), so the per-IP limits work when the proxy runs on the same machine. The session cookie becomes
`Secure` when `WEBAPP_PUBLIC_URL` is `https`.

**Data.** Accounts, credentials and refresh tokens are stored in SQLite at `CSC_DATA_DIR/csc.db`
(or `CSC_DB_PATH`), next to the key files. Back up that folder with `python server/admin.py backup`.

## Notes and next steps

- **Security trade-offs of this demo:** HTTP on localhost, web app sessions in memory, keys in unencrypted files
  instead of an HSM, and email confirmation instead of real identity proofing.
- **The code in the subject line** ("Your signing code: 123456") is convenient but appears in phone notifications.
  Remove it from `mailer.py` if that matters to you.
- **OAuth 2.0:** the natural next step is replacing PIN + code with an `oauth2/authorize` redirect (`scope=credential`).
  The provider then owns the login screen and the web app never sees any secret.
