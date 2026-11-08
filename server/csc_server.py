"""A toy Remote Signing Service Provider (RSSP) speaking CSC API v2.2,
delivering the one-time signing code by EMAIL, with self-service sign-up and
OAuth 2.0 credential creation.

CSC API methods (section 11 of the spec):

    POST /csc/v2/info
    POST /csc/v2/auth/login            (HTTP Basic, optional rememberMe)
    POST /csc/v2/auth/revoke
    POST /csc/v2/credentials/create    (needs an OAuth token with "credential-creation" authorization)
    POST /csc/v2/credentials/list
    POST /csc/v2/credentials/info
    POST /csc/v2/credentials/getChallenge (emails a 6-digit code: ChallengeResponse,
                                          challenge delivered out of band)
    POST /csc/v2/credentials/authorize (returns the SAD)
    POST /csc/v2/signatures/signHash

OAuth 2.0 authorization server (section 8.2), advertised by info as "oauth2":

    GET/POST /oauth2/authorize   Authorization Code flow, PKCE required, scopes "service" and
                                 "credential-creation", or RAR authorization_details of type
                                 "credential-creation". The login + consent page is served here;
                                 for a new credential the user also chooses the signing PIN on it.
    POST     /oauth2/token       grant_type=authorization_code (client secret via Basic or body)
    POST     /oauth2/revoke

Account enrollment (out of scope of the spec, section 1, so this is our own design):

    GET/POST /account/signup     name + email + password, sends a confirmation link
    GET      /account/verify     activates the account

Rules enforced, following the spec:
  * every CSC call except info needs "Authorization: Bearer <access token>"
  * a "credential-creation" token only grants credentials/create, once; a service
    token cannot create credentials
  * the certificate subject comes from the confirmed account, not from the client
  * authorization codes are single use, bound to client_id + redirect_uri + PKCE
  * the SAD is limited to numSignatures and expires (expiresIn)
  * SCAL 2 credentials: the SAD is bound to the hashes given at authorization
  * wrong PIN/OTP 3 times locks the credential
  * errors are returned as {"error": ..., "error_description": ...}
  * unknown CSC methods return 501 Not Implemented

This is a teaching demo: keys are software keys. Accounts, credentials and refresh tokens are stored
in SQLite (store.py, $CSC_DATA_DIR/csc.db); short-lived tokens, codes and SADs live in memory.
Configure SMTP in server/.env (see .env.example), then:
Run:  python server/csc_server.py   (listens on http://127.0.0.1:8080)
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
import re
import secrets
import sys
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import quote, unquote, urlencode

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, utils
from cryptography.x509.oid import NameOID
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response

sys.path.insert(0, str(Path(__file__).resolve().parent))
import mailer  # noqa: E402
import pages  # noqa: E402
import pki  # noqa: E402
from store import Store  # noqa: E402
from starlette.concurrency import run_in_threadpool  # noqa: E402


def _load_dotenv(path: Path) -> None:
    """Minimal .env loader (KEY=VALUE lines) so no extra dependency is needed."""
    if not path.exists():
        return
    for line in path.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            key, value = line.split("=", 1)
            os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))


_load_dotenv(Path(__file__).resolve().parent / ".env")

BASE = "/csc/v2"
SPECS = "2.2.0.0"

# OIDs used by this provider
OID_SHA256 = "2.16.840.1.101.3.4.2.1"
OID_RSA = "1.2.840.113549.1.1.1"  # rsaEncryption: hash algorithm given separately
OID_SHA256_RSA = "1.2.840.113549.1.1.11"  # sha256WithRSAEncryption

ACCESS_TOKEN_TTL = 3600
REFRESH_TOKEN_TTL = 30 * 24 * 3600
CREATION_TOKEN_TTL = 300
AUTH_CODE_TTL = 60
AUTHZ_TXN_TTL = 600
SAD_TTL = int(os.environ.get("CSC_SAD_TTL", "300"))
OTP_TTL = 300
RESEND_COOLDOWN = int(os.environ.get("CSC_RESEND_COOLDOWN", "30"))
MAX_AUTH_FAILURES = 3

# Sign-up and abuse limits (matter once the server is on the internet)
VERIFY_TTL = 24 * 3600
MIN_PASSWORD = 10
MAX_USERS = int(os.environ.get("CSC_MAX_USERS", "500"))
MAX_CREDENTIALS_PER_USER = int(os.environ.get("CSC_MAX_CREDENTIALS_PER_USER", "5"))
SIGNUPS_PER_IP_PER_HOUR = int(os.environ.get("CSC_SIGNUPS_PER_IP_PER_HOUR", "5"))
SIGNUPS_PER_EMAIL_PER_HOUR = 3
LOGIN_FAILURES_PER_IP = 20  # per 10 minutes, on the provider's own login page (the browser talks to us)
# auth/login is called by the signature app's backend, so every user of one app shares its IP.
# Counting per IP there would let one visitor lock everybody out; count per account instead.
LOGIN_FAILURES_PER_ACCOUNT = 10  # per 10 minutes
MAX_PENDING_AUTHZ = 5000
PBKDF2_ITERATIONS = 120_000

# Public base URL of this server (scheme + host, no trailing slash). Needed behind a
# reverse proxy so that links in emails and the "oauth2" info field are right.
PUBLIC_URL = os.environ.get("CSC_PUBLIC_URL", "").rstrip("/")

# The OAuth client allowed to use the authorization server: the demo web app.
# "The way this client_id is set up ... is out of scope" (8.2), so it is configured here.
OAUTH_CLIENTS = {
    os.environ.get("CSC_OAUTH_CLIENT_ID", "csc-signer"): {
        "name": "CSC Signer web app",
        "secret": os.environ.get("CSC_OAUTH_CLIENT_SECRET", "csc-signer-demo-secret"),
        "redirect_uris": [u.strip() for u in os.environ.get(
            "CSC_OAUTH_REDIRECT_URIS", "http://127.0.0.1:8000/oauth/callback").split(",") if u.strip()],
    }
}

# Certificate policies a client may request in credentialCreationRequest.certificatePolicy
POLICIES = {
    "0.4.0.194112.1.2": {  # ETSI EN 319 411-2 QCP-n-qscd
        "label": "Qualified certificate on a QSCD (QCP-n-qscd)",
        "description": "Qualified signature (SCAL 2, PIN + email code)",
        "unlock": "Your PIN and a code we email you",
        "scal": "2", "expression": "PIN AND EMAIL_OTP", "multisign": 5,
    },
    "0.4.0.2042.1.1": {  # ETSI EN 319 411-1 NCP
        "label": "Normalized certificate (NCP)",
        "description": "Advanced signature (SCAL 1, PIN only)",
        "unlock": "Your PIN",
        "scal": "1", "expression": "PIN", "multisign": 10,
    },
}
CREATION_TYPES = {"https://cloudsignatureconsortium.org/2025/credential-creation", "credential-creation"}

# Set CSC_DEMO_LEAK_OTP=1 to expose GET /demo/otp/{credentialID} so scripted
# demos and tests can read the "SMS". Off by default.
LEAK_OTP = os.environ.get("CSC_DEMO_LEAK_OTP") == "1"


# --------------------------------------------------------------------------- #
# Errors
# --------------------------------------------------------------------------- #
class CSCError(Exception):
    def __init__(self, status: int, error: str, description: str):
        self.status, self.error, self.description = status, error, description


def bad(description: str, error: str = "invalid_request") -> CSCError:
    return CSCError(400, error, description)


# --------------------------------------------------------------------------- #
# Secrets at rest: passwords and PINs are stored as PBKDF2 hashes
# --------------------------------------------------------------------------- #
def hash_secret(value: str) -> str:
    salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", value.encode(), salt, PBKDF2_ITERATIONS)
    return f"{salt.hex()}${dk.hex()}"


def verify_secret(value: str, stored: str) -> bool:
    salt, _, digest = stored.partition("$")
    dk = hashlib.pbkdf2_hmac("sha256", value.encode(), bytes.fromhex(salt), PBKDF2_ITERATIONS)
    return secrets.compare_digest(dk.hex(), digest)


# --------------------------------------------------------------------------- #
# State
# --------------------------------------------------------------------------- #
@dataclass
class Credential:
    id: str
    owner: str
    description: str
    key: object
    cert: x509.Certificate
    pin_hash: str
    scal: str  # "1" or "2"
    expression: str  # e.g. "PIN AND EMAIL_OTP"
    multisign: int
    enabled: bool = True
    failures: int = 0


@dataclass
class SAD:
    credential_id: str
    user: str
    remaining: int
    hashes: set[str] | None  # None = not bound to hashes (SCAL 1)
    expires_at: float


@dataclass
class Token:
    user: str
    expires_at: float
    scope: str  # "service" | "credential-creation"
    client_id: str | None = None  # None for tokens from auth/login
    details: list | None = None  # approved RAR authorization_details
    pin_hash: str | None = None  # PIN chosen on the consent page (credential-creation)


@dataclass
class AuthzTxn:
    """An oauth2/authorize request waiting for the user to log in and approve."""
    client_id: str
    redirect_uri: str
    redirect_uri_given: bool
    state: str | None
    scope: str
    details: list | None
    challenge: str
    method: str
    expires_at: float


@dataclass
class AuthCode:
    client_id: str
    redirect_uri: str
    redirect_uri_given: bool
    user: str
    scope: str
    details: list | None
    challenge: str
    method: str
    expires_at: float
    pin_hash: str | None = None
    used: bool = False
    token: str | None = None


class RateLimiter:
    """Sliding-window counters keyed by e.g. client IP or email address."""

    def __init__(self):
        self.events: dict[str, deque] = defaultdict(deque)

    def count(self, key: str, window: float) -> int:
        q, now = self.events[key], time.time()
        while q and q[0] < now - window:
            q.popleft()
        return len(q)

    def hit(self, key: str) -> None:
        self.events[key].append(time.time())


@dataclass
class State:
    store: Store  # persistent: users, email confirmations, credentials, refresh tokens
    access_tokens: dict[str, Token] = field(default_factory=dict)
    otps: dict[str, tuple[str, float, float]] = field(default_factory=dict)  # code, expires, sent_at
    sads: dict[str, SAD] = field(default_factory=dict)
    authz: dict[str, AuthzTxn] = field(default_factory=dict)
    codes: dict[str, AuthCode] = field(default_factory=dict)
    limiter: RateLimiter = field(default_factory=RateLimiter)
    keys: dict[str, tuple] = field(default_factory=dict)  # credential id -> (private key, certificate), cached
    ca_key: object = None
    ca_cert: x509.Certificate | None = None


def db_path() -> Path:
    return Path(os.environ.get("CSC_DB_PATH") or pki.DATA_DIR / "csc.db")


def _keep_or_hash(secret: str, stored: str | None) -> str:
    """Reuse the stored hash if the configured secret didn't change (hashes are salted, so compare)."""
    return stored if stored and verify_secret(secret, stored) else hash_secret(secret)


DEMO_CREDENTIALS = [  # (id, certificate CN, description, PIN variable, default PIN, SCAL, expression, multisign)
    ("cred-alice-qes", "Alice Demo (QES)", "Qualified signature (SCAL 2, PIN + email code)",
     "DEMO_PIN_QES", "123456", "2", "PIN AND EMAIL_OTP", 5),
    ("cred-alice-adv", "Alice Demo (AdES)", "Advanced signature (SCAL 1, PIN only)",
     "DEMO_PIN_ADV", "1234", "1", "PIN", 10),
]


def build_state() -> State:
    """Open (or create and migrate) the database and bring the demo account to its configured state."""
    ca_key, ca_cert = pki.load_or_create_ca()
    st = State(store=Store(db_path()))
    st.ca_key, st.ca_cert = ca_key, ca_cert

    alice = st.store.user("alice")
    st.store.upsert_user("alice", os.environ.get("DEMO_USER_EMAIL", "alice@example.com"), "Alice", "Demo",
                         _keep_or_hash(os.environ.get("DEMO_USER_PASSWORD", "alice-password"),
                                       alice and alice["password_hash"]), verified=True)
    for cid, cn, description, pin_var, pin_default, scal, expression, multisign in DEMO_CREDENTIALS:
        st.keys[cid] = pki.load_or_create_credential(cid, cn, ca_key, ca_cert)
        row = st.store.credential(cid)
        st.store.upsert_demo_credential(cid, "alice", description,
                                        _keep_or_hash(os.environ.get(pin_var, pin_default), row and row["pin_hash"]),
                                        scal, expression, multisign)
    return st


STATE = build_state()
app = FastAPI(title="CSC demo RSSP", version=SPECS, docs_url="/docs")


@app.exception_handler(CSCError)
async def _csc_error(_: Request, exc: CSCError):
    return JSONResponse(status_code=exc.status, content={"error": exc.error, "error_description": exc.description},
                        headers={"Cache-Control": "no-store"})


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
async def body(request: Request) -> dict:
    raw = await request.body()
    if not raw.strip():
        return {}
    try:
        data = await request.json()
    except ValueError:
        raise bad("Malformed JSON body")
    if not isinstance(data, dict):
        raise bad("JSON body must be an object")
    return data


def bearer(request: Request, scope: str = "service") -> tuple[str, Token]:
    """Return (token string, token) if the bearer token grants `scope`."""
    header = request.headers.get("authorization", "")
    if not header.startswith("Bearer "):
        raise bad("Malformed authorization header.")
    value = header[7:].strip()
    tok = STATE.access_tokens.get(value)
    if tok is None:
        raise CSCError(401, "invalid_token", "The access token is not valid")
    if tok.expires_at < time.time():
        STATE.access_tokens.pop(value, None)
        raise CSCError(401, "expired_token", "The access token is expired")
    if tok.scope != scope:
        raise CSCError(403, "insufficient_scope", f"The access token does not grant {scope} authorization")
    return value, tok


def bearer_user(request: Request) -> str:
    return bearer(request, "service")[1].user


def req_str(data: dict, name: str) -> str:
    value = data.get(name)
    if not isinstance(value, str) or not value:
        raise bad(f"Missing (or invalid type) string parameter {name}")
    return value


def as_credential(row: dict) -> Credential:
    """A credentials row plus its key and certificate (read from disk once, then cached)."""
    if row["id"] not in STATE.keys:
        STATE.keys[row["id"]] = pki.load_credential(row["id"])
    key, cert = STATE.keys[row["id"]]
    return Credential(id=row["id"], owner=row["owner"], description=row["description"], key=key, cert=cert,
                      pin_hash=row["pin_hash"], scal=row["scal"], expression=row["expression"],
                      multisign=row["multisign"], enabled=bool(row["enabled"]), failures=row["failures"])


def credential_for(data: dict, user: str) -> Credential:
    cid = req_str(data, "credentialID")
    row = STATE.store.credential(cid)
    if row is None or row["owner"] != user:
        raise bad("Invalid parameter credentialID")
    return as_credential(row)


DN_NAMES = {NameOID.GIVEN_NAME: "GN", NameOID.SURNAME: "SN"}  # print these instead of bare OIDs


def b64_cert(cert: x509.Certificate) -> str:
    return base64.b64encode(cert.public_bytes(serialization.Encoding.DER)).decode()


def gen_time(t) -> str:
    return t.strftime("%Y%m%d%H%M%SZ")


def decode_hashes(values, algo_oid: str) -> list[bytes]:
    if not isinstance(values, list):
        raise bad("Missing (or invalid type) array parameter hashes")
    if not values:
        raise bad("Empty hashes array")
    out = []
    for v in values:
        try:
            raw = base64.b64decode(v, validate=True) if isinstance(v, str) else None
        except (binascii.Error, ValueError):
            raw = None
        if raw is None:
            raise bad("Invalid Base64 hash string parameter")
        if algo_oid == OID_SHA256 and len(raw) != 32:
            raise bad("Invalid digest value length")
        out.append(raw)
    return out


def canon(h: bytes) -> str:
    return base64.b64encode(h).decode()


def auth_objects(cred: Credential) -> list[dict]:
    objs = [{"type": "Password", "id": "PIN", "format": "N", "label": "PIN",
             "description": "Please enter the signature PIN"}]
    if "EMAIL_OTP" in cred.expression:
        to = mailer.mask(STATE.store.user(cred.owner)["email"])
        objs.append({"type": "ChallengeResponse", "id": "EMAIL_OTP", "format": "N",
                     "label": "Email code",
                     "description": f"Request a code with credentials/getChallenge, then enter the 6 digits sent to {to}"})
    return objs


def credential_info(cred: Credential, certificates="single", cert_info=False, auth_info=False) -> dict:
    if certificates not in ("none", "single", "chain"):
        raise bad("Invalid parameter certificates")
    c = cred.cert
    cert: dict = {"status": "valid" if c.not_valid_after_utc.timestamp() > time.time() else "expired"}
    if certificates == "single":
        cert["certificates"] = [b64_cert(c)]
    elif certificates == "chain":
        cert["certificates"] = [b64_cert(c), b64_cert(STATE.ca_cert)]
    if cert_info:
        cert.update({
            "issuerDN": c.issuer.rfc4514_string(DN_NAMES),
            "serialNumber": format(c.serial_number, "X"),
            "subjectDN": c.subject.rfc4514_string(DN_NAMES),
            "validFrom": gen_time(c.not_valid_before_utc),
            "validTo": gen_time(c.not_valid_after_utc),
        })
    info = {
        "description": cred.description,
        "key": {"status": "enabled" if cred.enabled else "disabled",
                "algo": [OID_SHA256_RSA, OID_RSA], "len": cred.key.key_size},
        "cert": cert,
        "auth": {"mode": "explicit"},
        "SCAL": cred.scal,
        "multisign": cred.multisign,
        "lang": "en-US",
    }
    if auth_info:
        info["auth"].update({"expression": cred.expression, "objects": auth_objects(cred)})
    return info


def check_auth_data(cred: Credential, auth_data) -> None:
    """Evaluate a simple 'A AND B' / 'A OR B' expression against authData."""
    if not isinstance(auth_data, list):
        raise bad("Missing (or invalid type) array parameter authData")
    given = {o.get("id"): o.get("value") for o in auth_data if isinstance(o, dict)}

    def ok(obj_id: str) -> bool:
        if obj_id == "PIN":
            return verify_secret(str(given.get("PIN", "")), cred.pin_hash)
        if obj_id == "EMAIL_OTP":
            sent = STATE.otps.get(cred.id)
            if not sent or sent[1] < time.time():
                return False
            return secrets.compare_digest(str(given.get("EMAIL_OTP", "")), sent[0])
        return False

    if " OR " in cred.expression:
        passed = any(ok(t.strip()) for t in cred.expression.split(" OR "))
    else:
        passed = all(ok(t.strip()) for t in cred.expression.split(" AND "))

    if not passed:
        if STATE.store.record_auth_failure(cred.id, MAX_AUTH_FAILURES):  # stays locked across restarts
            raise bad("Credential locked")
        raise bad("The authentication data is invalid", "invalid_authentication_data")
    if cred.failures:
        STATE.store.reset_failures(cred.id)
    STATE.otps.pop(cred.id, None)  # an OTP is single-use


def public_base(request: Request) -> str:
    return PUBLIC_URL or str(request.base_url).rstrip("/")


def client_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def html(content: str, status: int = 200) -> HTMLResponse:
    # The consent page must not be framed (clickjacking) or cached.
    return HTMLResponse(content, status_code=status, headers={
        "X-Frame-Options": "DENY", "Content-Security-Policy": "frame-ancestors 'none'",
        "Cache-Control": "no-store", "Referrer-Policy": "no-referrer"})


def purge_expired() -> None:
    now = time.time()
    STATE.store.purge_expired(now)
    for store in (STATE.authz, STATE.codes):
        for k, v in list(store.items()):
            if v.expires_at < now:
                store.pop(k)
    for k, t in list(STATE.access_tokens.items()):
        if t.expires_at < now:
            STATE.access_tokens.pop(k)


def check_password(username: str, password: str) -> str | None:
    """Return the canonical username if the password is right, else None (unverified accounts included)."""
    username = username.strip().lower()
    record = STATE.store.user(username)
    if record is None:
        verify_secret(password, hash_secret("x"))  # same cost either way: no user enumeration by timing
        return None
    if not verify_secret(password, record["password_hash"]):
        return None
    return username


# --------------------------------------------------------------------------- #
# CSC API endpoints
# --------------------------------------------------------------------------- #
@app.post(f"{BASE}/info")
async def info(request: Request):
    await body(request)
    base = public_base(request)
    return {
        "specs": SPECS,
        "name": "CSC Demo Trust Services",
        "logo": f"{base}/logo.png",
        "region": "BE",
        "lang": "en-US",
        "description": "Toy remote signing service for learning the CSC API. Not for real signatures.",
        "authType": ["basic", "oauth2code"],
        "oauth2": f"{base}/",
        "supportsRar": True,
        "methods": ["auth/login", "auth/revoke", "credentials/create", "credentials/list", "credentials/info",
                    "credentials/getChallenge", "credentials/authorize", "signatures/signHash"],
        "supportedHashTypes": [OID_SHA256],
        "asynchronousOperationMode": False,
        "validationInfo": False,
        "signAlgorithms": {"algos": [OID_SHA256_RSA, OID_RSA]},
        "signature_formats": {"formats": [], "envelope_properties": []},
        "conformance_levels": [],
    }


@app.post(f"{BASE}/auth/login")
async def auth_login(request: Request):
    data = await body(request)
    user = None
    refresh = data.get("refresh_token")
    if refresh:
        if not isinstance(refresh, str):
            raise bad("Invalid string parameter: refresh_token")
        user = STATE.store.refresh_token_user(refresh, time.time())
        if user is None:
            raise bad("Invalid refresh_token")
    else:
        header = request.headers.get("authorization", "")
        if not header.startswith("Basic "):
            raise CSCError(401, "invalid_request", "Malformed authentication parameter.")
        try:
            decoded = base64.b64decode(header[6:]).decode()
            username, password = decoded.split(":", 1)
        except (ValueError, binascii.Error, UnicodeDecodeError):
            raise bad("Malformed username-password.")
        account_key = f"login-account:{username.strip().lower()}"
        if STATE.limiter.count(account_key, 600) >= LOGIN_FAILURES_PER_ACCOUNT:
            raise CSCError(429, "invalid_request", "Too many failed logins for this account. Try again later")
        user = check_password(username, password)
        if user is None or not STATE.store.user(user)["verified"]:
            STATE.limiter.hit(account_key)
            raise bad("An error occurred during authentication process", "authentication_error")

    token = secrets.token_urlsafe(32)
    STATE.access_tokens[token] = Token(user, time.time() + ACCESS_TOKEN_TTL, "service")
    out = {"access_token": token, "expires_in": ACCESS_TOKEN_TTL}
    if data.get("rememberMe") is True:
        rt = secrets.token_urlsafe(32)
        STATE.store.add_refresh_token(rt, user, time.time() + REFRESH_TOKEN_TTL)
        out["refresh_token"] = rt
    return out


@app.post(f"{BASE}/auth/revoke")
async def auth_revoke(request: Request):
    bearer_user(request)
    data = await body(request)
    token = req_str(data, "token")
    hint = data.get("token_type_hint")
    if hint not in (None, "access_token", "refresh_token"):
        raise bad("Invalid string parameter token_type_hint")
    if token in STATE.access_tokens:
        STATE.access_tokens.pop(token)
    elif (user := STATE.store.revoke_refresh_token(token)) is not None:
        for t, tok in list(STATE.access_tokens.items()):
            if tok.user == user:
                STATE.access_tokens.pop(t)
    else:
        raise bad("Invalid string parameter token")
    return Response(status_code=204)


def creation_expression(policy: dict, auth_data) -> str:
    """credentials/create authData: the auth objects the client will implement for this credential."""
    if auth_data is None:
        return policy["expression"]
    if not isinstance(auth_data, list) or not all(isinstance(o, dict) for o in auth_data):
        raise bad("Invalid parameter “authData”")
    ids = {o.get("id") for o in auth_data}
    if "PIN" not in ids or not ids <= {"PIN", "EMAIL_OTP"}:
        raise bad("Invalid parameter “authData”")
    expression = "PIN AND EMAIL_OTP" if "EMAIL_OTP" in ids else "PIN"
    if policy["scal"] == "2" and expression == "PIN":
        raise bad("Invalid parameter “authData”: this certificate policy requires PIN AND EMAIL_OTP")
    return expression


@app.post(f"{BASE}/credentials/create")
async def credentials_create(request: Request):
    token_value, tok = bearer(request, "credential-creation")
    data = await body(request)

    ccr = data.get("credentialCreationRequest")
    if not isinstance(ccr, dict):
        raise bad("Missing (or invalid type) parameter “credentialCreationRequest”")
    policy_oid = ccr.get("certificatePolicy")
    if not isinstance(policy_oid, str) or not policy_oid:
        raise bad("Missing (or invalid type) string parameter certificatePolicy")
    policy = POLICIES.get(policy_oid)
    if policy is None:
        raise bad("Invalid parameter certificatePolicy")
    if "subjectData" in ccr and not isinstance(ccr["subjectData"], dict):
        raise bad("Invalid parameter subjectData")
    if tok.details is not None:
        authorized = tok.details[0]["credentialCreationRequest"]["certificatePolicy"]
        if policy_oid != authorized:
            raise CSCError(403, "access_denied", "certificatePolicy differs from the one the user authorized")

    want_info = data.get("credentialInfo", False)
    if not isinstance(want_info, bool):
        raise bad("Invalid parameter “credentialInfo”")
    certificates = data.get("certificates", "single")
    if certificates not in ("none", "single", "chain"):
        raise bad("Invalid parameter “certificates”")
    cert_info = data.get("certInfo", False)
    if not isinstance(cert_info, bool):
        raise bad("Invalid parameter “certInfo”")
    expression = creation_expression(policy, data.get("authData"))

    user = STATE.store.user(tok.user)
    if user is None or not tok.pin_hash:
        raise CSCError(401, "invalid_token", "The access token is not valid")
    if STATE.store.credential_count(tok.user) >= MAX_CREDENTIALS_PER_USER:
        raise CSCError(403, "access_denied", f"Credential limit reached ({MAX_CREDENTIALS_PER_USER} per user)")

    # The creation authorization is for one credential: consume it before the slow key generation.
    STATE.access_tokens.pop(token_value, None)
    cid = "cred-" + secrets.token_hex(8)
    # The subject comes from the confirmed account; the client's subjectData is ignored (allowed by 11.4).
    key, cert = await run_in_threadpool(pki.issue_credential, cid, user["given_name"], user["family_name"],
                                        policy_oid, STATE.ca_key, STATE.ca_cert)
    cred = Credential(id=cid, owner=tok.user, description=policy["description"], key=key, cert=cert,
                      pin_hash=tok.pin_hash, scal=policy["scal"], expression=expression,
                      multisign=policy["multisign"])
    STATE.keys[cid] = (key, cert)
    STATE.store.add_credential(cid, tok.user, cred.description, policy_oid, cred.pin_hash, cred.scal,
                               cred.expression, cred.multisign)
    print(f"  [create] {cid} for {tok.user} under policy {policy_oid}", flush=True)
    out = {"credentialID": cid,
           **credential_info(cred, certificates if want_info else "none", cert_info and want_info)}
    return JSONResponse(status_code=201, content=out)


@app.post(f"{BASE}/credentials/list")
async def credentials_list(request: Request):
    user = bearer_user(request)
    data = await body(request)
    if data.get("userID") not in (None, ""):
        raise bad("userID parameter MUST be null")
    creds = [as_credential(row) for row in STATE.store.credentials_of(user)]
    only_valid = data.get("onlyValid") is True
    if only_valid:
        creds = [c for c in creds if c.enabled]
    out: dict = {"credentialIDs": [c.id for c in creds]}
    if data.get("credentialInfo") is True:
        out["credentialInfos"] = [
            {"credentialID": c.id, **credential_info(c, data.get("certificates", "single"),
                                                     data.get("certInfo") is True, data.get("authInfo") is True)}
            for c in creds
        ]
    if only_valid:
        out["onlyValid"] = True
    return out


@app.post(f"{BASE}/credentials/info")
async def credentials_info(request: Request):
    user = bearer_user(request)
    data = await body(request)
    cred = credential_for(data, user)
    return credential_info(cred, data.get("certificates", "single"),
                           data.get("certInfo") is True, data.get("authInfo") is True)


@app.post(f"{BASE}/credentials/getChallenge")
async def credentials_get_challenge(request: Request):
    user = bearer_user(request)
    data = await body(request)
    cred = credential_for(data, user)
    obj_id = data.get("authObjectID")
    if obj_id != "EMAIL_OTP" or "EMAIL_OTP" not in cred.expression:
        raise bad("Invalid parameter authObjectID")
    if not cred.enabled:
        raise bad("Credential locked")
    previous = STATE.otps.get(cred.id)
    if previous and time.time() - previous[2] < RESEND_COOLDOWN:
        wait = int(RESEND_COOLDOWN - (time.time() - previous[2])) + 1
        raise CSCError(429, "invalid_request", f"A code was just sent. Try again in {wait} s")

    code = f"{secrets.randbelow(10**6):06d}"
    to = STATE.store.user(user)["email"]
    try:
        await run_in_threadpool(mailer.send_code, to, code, cred.description, OTP_TTL // 60)
    except mailer.MailError as exc:
        print(f"  [email] delivery failed: {exc}", flush=True)
        raise CSCError(503, "temporarily_unavailable", "Could not deliver the code by email")
    STATE.otps[cred.id] = (code, time.time() + OTP_TTL, time.time())
    # 204: the challenge was delivered out of band (by email)
    return Response(status_code=204)


@app.post(f"{BASE}/credentials/authorize")
async def credentials_authorize(request: Request):
    user = bearer_user(request)
    data = await body(request)
    cred = credential_for(data, user)
    if not cred.enabled:
        raise bad("The credential identified by credentialID is disabled")

    num = data.get("numSignatures")
    if not isinstance(num, int) or isinstance(num, bool):
        raise bad("Missing (or invalid type) integer parameter numSignatures")
    if num < 1:
        raise bad("Invalid value for parameter numSignatures")
    if num > cred.multisign:
        raise bad("Numbers of signatures is too high")

    bound = None
    if "hashes" in data or cred.scal == "2":
        algo = data.get("hashAlgorithmOID")
        if algo != OID_SHA256:
            raise bad("Missing (or invalid type) string parameter hashAlgorithmOID" if algo is None
                      else "Invalid parameter hashAlgorithmOID")
        hashes_raw = decode_hashes(data.get("hashes"), algo)
        if cred.scal == "2" and len(hashes_raw) != num:
            raise bad("At SCAL 2 the number of hashes must equal numSignatures")
        bound = {canon(h) for h in hashes_raw}

    check_auth_data(cred, data.get("authData"))

    sad_value = secrets.token_urlsafe(32)
    STATE.sads[sad_value] = SAD(cred.id, user, num, bound, time.time() + SAD_TTL)
    return {"SAD": sad_value, "expiresIn": SAD_TTL}


@app.post(f"{BASE}/signatures/signHash")
async def signatures_sign_hash(request: Request):
    user = bearer_user(request)
    data = await body(request)
    cred = credential_for(data, user)

    sign_algo = req_str(data, "signAlgo")
    if sign_algo not in (OID_RSA, OID_SHA256_RSA):
        raise bad("Invalid parameter signAlgo")
    hash_algo = data.get("hashAlgorithmOID")
    if sign_algo == OID_SHA256_RSA:
        if hash_algo not in (None, OID_SHA256):
            raise bad("String parameter hashAlgorithmOID contradicts with signAlgo signAlgoParams parameter")
        hash_algo = OID_SHA256
    elif hash_algo is None:
        raise bad("Missing (or invalid type) string parameter hashAlgorithmOID")
    elif hash_algo != OID_SHA256:
        raise bad("Invalid parameter hashAlgorithmOID")
    if data.get("operationMode", "S") != "S":
        raise bad("Invalid parameter operationMode")

    digests = decode_hashes(data.get("hashes"), hash_algo)

    sad_value = req_str(data, "SAD")
    sad = STATE.sads.get(sad_value)
    if sad is None or sad.credential_id != cred.id or sad.user != user:
        raise bad("Invalid parameter SAD")
    if sad.expires_at < time.time():
        STATE.sads.pop(sad_value, None)
        raise bad("SAD expired")
    if len(digests) > sad.remaining:
        raise bad("Number of hashes exceeds the signatures authorized by the SAD")
    if sad.hashes is not None:
        for d in digests:
            if canon(d) not in sad.hashes:
                raise bad("Hash is not authorized by neither SAD nor an access token with scope “credential”.")

    # --- the "HSM": sign each pre-computed hash with the private key ---------
    signatures = []
    for d in digests:
        sig = cred.key.sign(d, padding.PKCS1v15(), utils.Prehashed(hashes.SHA256()))
        signatures.append(base64.b64encode(sig).decode())
        if sad.hashes is not None:
            sad.hashes.discard(canon(d))

    sad.remaining -= len(digests)
    if sad.remaining <= 0:
        STATE.sads.pop(sad_value, None)  # all authorized signatures used: invalidate
    return {"signatures": signatures}


@app.post(BASE + "/{method:path}")
async def not_implemented(method: str):
    raise CSCError(501, "invalid_request", f"Method {method} is not implemented by this service")


# --------------------------------------------------------------------------- #
# Account enrollment (outside the CSC API: the spec leaves it out of scope)
# --------------------------------------------------------------------------- #
EMAIL_RE = re.compile(r"^[^@\s:]+@[^@\s:]+\.[^@\s:]+$")


def safe_next(value: str | None) -> str:
    """Only allow returning to a pending oauth2/authorize request on this server (no open redirect)."""
    if value and value.startswith("/oauth2/authorize?") and "\\" not in value and len(value) <= 4096:
        return value
    return ""


def valid_name(value: str) -> bool:
    return 0 < len(value) <= 64 and value.isprintable() and not any(c in value for c in '<>"\\=+;,/')


@app.get("/account/signup")
async def signup_form(request: Request):
    return html(pages.signup({}, safe_next(request.query_params.get("next")), min_password=MIN_PASSWORD))


@app.post("/account/signup")
async def signup_submit(request: Request):
    form = await request.form()
    values = {k: str(form.get(k, "")).strip() for k in ("given_name", "family_name", "email")}
    values["email"] = values["email"].lower()
    password, password2 = str(form.get("password", "")), str(form.get("password2", ""))
    next_url = safe_next(str(form.get("next", "")))

    def again(error: str, status: int = 400):
        return html(pages.signup(values, next_url, error, MIN_PASSWORD), status)

    if not (valid_name(values["given_name"]) and valid_name(values["family_name"])):
        return again("Enter your given and family name (up to 64 characters, no special symbols).")
    if len(values["email"]) > 254 or not EMAIL_RE.match(values["email"]):
        return again("Enter a valid email address.")
    if not MIN_PASSWORD <= len(password) <= 128:
        return again(f"The password must have {MIN_PASSWORD} to 128 characters.")
    if password != password2:
        return again("The two passwords are different.")

    ip_key, mail_key = f"signup:{client_ip(request)}", f"signup-mail:{values['email']}"
    if (STATE.limiter.count(ip_key, 3600) >= SIGNUPS_PER_IP_PER_HOUR
            or STATE.limiter.count(mail_key, 3600) >= SIGNUPS_PER_EMAIL_PER_HOUR):
        return again("Too many sign-ups from here. Try again in an hour.", 429)

    purge_expired()
    username = values["email"]
    existing = STATE.store.user(username)
    if existing and existing["verified"]:
        return again("An account with this email already exists. Sign in instead.", 409)
    if existing is None and STATE.store.user_count() >= MAX_USERS:
        return again("Sign-ups are closed on this demo server for now.", 503)

    # (Re)create the unconfirmed account; any older confirmation link stops working.
    token = secrets.token_urlsafe(32)
    STATE.store.create_unverified_user(username, values["email"], values["given_name"], values["family_name"],
                                       hash_secret(password), token, time.time() + VERIFY_TTL, next_url)
    link = f"{public_base(request)}/account/verify?token={token}"
    try:
        await run_in_threadpool(mailer.send_verification, values["email"], values["given_name"], link,
                                VERIFY_TTL // 3600)
    except mailer.MailError as exc:
        print(f"  [email] delivery failed: {exc}", flush=True)
        STATE.store.delete_unverified_user(username)
        return again("We couldn't send the confirmation email. Try again later.", 503)
    STATE.limiter.hit(ip_key)
    STATE.limiter.hit(mail_key)
    return html(pages.signup_sent(mailer.mask(values["email"]), VERIFY_TTL // 3600))


@app.get("/account/verify")
async def verify_email(request: Request):
    entry = STATE.store.confirm_email(request.query_params.get("token", ""), time.time())
    if entry is None:
        return html(pages.message("Link expired", "This confirmation link is invalid or has expired. "
                                  "Sign up again with the same email to get a new one."), 400)
    username, next_url = entry
    print(f"  [signup] {username} confirmed their email", flush=True)
    return html(pages.verified(username, next_url or None))


# --------------------------------------------------------------------------- #
# OAuth 2.0 authorization server (section 8.2)
# --------------------------------------------------------------------------- #
PKCE_RE = re.compile(r"^[A-Za-z0-9\-._~]{43,128}$")


def with_query(uri: str, params: dict) -> str:
    params = {k: v for k, v in params.items() if v is not None}
    return uri + ("&" if "?" in uri else "?") + urlencode(params)


def parse_creation_details(raw: str) -> list:
    """Validate RAR authorization_details for credential creation. Raises ValueError with a message."""
    try:
        details = json.loads(raw)
    except ValueError:
        raise ValueError("authorization_details is not valid JSON")
    if not isinstance(details, list) or len(details) != 1 or not isinstance(details[0], dict):
        raise ValueError("authorization_details must be an array with one object")
    d = details[0]
    if d.get("type") not in CREATION_TYPES:
        raise ValueError("Unsupported authorization_details type")
    ccr = d.get("credentialCreationRequest")
    if not isinstance(ccr, dict):
        raise ValueError("Missing (or invalid type) parameter credentialCreationRequest")
    if ccr.get("certificatePolicy") not in POLICIES:
        raise ValueError("Invalid parameter certificatePolicy")
    if "subjectData" in ccr and not isinstance(ccr["subjectData"], dict):
        raise ValueError("Invalid parameter subjectData")
    acr = d.get("acr_values")
    if acr is not None and not (isinstance(acr, list) and all(isinstance(a, str) for a in acr)):
        raise ValueError("Invalid parameter acr_values")
    return details


@app.get("/oauth2/authorize")
async def oauth2_authorize(request: Request):
    q = request.query_params
    client = OAUTH_CLIENTS.get(q.get("client_id", ""))
    if client is None:
        return html(pages.message("Unknown application", "The client_id in this request is not registered."), 400)
    redirect_uri = q.get("redirect_uri") or client["redirect_uris"][0]
    if redirect_uri not in client["redirect_uris"]:
        # Never redirect to an unregistered URI (RFC 6749 4.1.2.1)
        return html(pages.message("Invalid redirect", "The redirect_uri is not registered for this application."), 400)
    state = q.get("state")

    def fail(error: str, description: str):
        return RedirectResponse(with_query(redirect_uri, {"error": error, "error_description": description,
                                                          "state": state}), status_code=302)

    if q.get("request_uri"):
        return fail("invalid_request", "Pushed authorization requests are not supported")
    if q.get("response_type") != "code":
        return fail("unsupported_response_type", "response_type must be code")
    challenge, method = q.get("code_challenge", ""), q.get("code_challenge_method", "plain")
    if not PKCE_RE.match(challenge):
        return fail("invalid_request", "Missing or invalid parameter code_challenge")
    if method not in ("S256", "plain"):
        return fail("invalid_request", "Invalid parameter code_challenge_method")
    if q.get("scope") and q.get("authorization_details"):
        return fail("invalid_request", "scope and authorization_details cannot be used together")

    details = None
    if q.get("authorization_details"):
        try:
            details = parse_creation_details(q["authorization_details"])
        except ValueError as exc:
            return fail("invalid_request", str(exc))
        scope = "credential-creation"
    else:
        scope = q.get("scope") or "service"
        if scope not in ("service", "credential-creation"):
            return fail("invalid_scope", "Supported scopes: service, credential-creation")

    purge_expired()
    if len(STATE.authz) >= MAX_PENDING_AUTHZ:
        return fail("temporarily_unavailable", "Too many pending authorization requests")
    txn = secrets.token_urlsafe(24)
    STATE.authz[txn] = AuthzTxn(q["client_id"], redirect_uri, "redirect_uri" in q, state, scope, details,
                                challenge, method, time.time() + AUTHZ_TXN_TTL)
    return html(render_authorize(request, txn))


def render_authorize(request: Request, txn: str, username: str = "", error: str | None = None,
                     status: int = 200) -> str:
    t = STATE.authz[txn]
    oid = t.details[0]["credentialCreationRequest"]["certificatePolicy"] if t.details else None
    if request.method == "GET":
        back = f"{request.url.path}?{request.url.query}"
    else:  # rebuild the original request so "create an account" can come back to it
        back = with_query("/oauth2/authorize", {
            "response_type": "code", "client_id": t.client_id,
            "redirect_uri": t.redirect_uri if t.redirect_uri_given else None, "state": t.state,
            "code_challenge": t.challenge, "code_challenge_method": t.method,
            "scope": None if t.details else t.scope,
            "authorization_details": json.dumps(t.details) if t.details else None})
    return pages.authorize(txn=txn, client_name=OAUTH_CLIENTS[t.client_id]["name"], scope=t.scope,
                           policy=POLICIES.get(oid) if oid else None, policy_oid=oid,
                           signup_url="/account/signup?next=" + quote(back, safe=""),
                           username=username, error=error)


@app.post("/oauth2/authorize")
async def oauth2_authorize_submit(request: Request):
    form = await request.form()
    txn = str(form.get("txn", ""))
    t = STATE.authz.get(txn)
    if t is None or t.expires_at < time.time():
        return html(pages.message("Request expired", "This sign-in request has expired. "
                                  "Go back to the app and start again."), 400)

    if form.get("decision") != "approve":
        STATE.authz.pop(txn)
        return RedirectResponse(with_query(t.redirect_uri, {"error": "access_denied",
                                "error_description": "The user denied the request", "state": t.state}), 302)

    username = str(form.get("username", ""))
    ip_key = f"login:{client_ip(request)}"
    if STATE.limiter.count(ip_key, 600) >= LOGIN_FAILURES_PER_IP:
        return html(render_authorize(request, txn, username, "Too many failed attempts. Wait a few minutes."), 429)
    user = check_password(username, str(form.get("password", "")))
    if user is None:
        STATE.limiter.hit(ip_key)
        return html(render_authorize(request, txn, username, "Wrong email/username or password."), 400)
    record = STATE.store.user(user)
    if not record["verified"]:
        return html(render_authorize(request, txn, username,
                                     "Confirm your email first: open the link we sent you."), 400)

    pin_hash = None
    approved = None
    if t.scope == "credential-creation":
        pin, pin2 = str(form.get("pin", "")), str(form.get("pin2", ""))
        if not re.fullmatch(r"\d{4,8}", pin):
            return html(render_authorize(request, txn, username, "The PIN must be 4 to 8 digits."), 400)
        if pin != pin2:
            return html(render_authorize(request, txn, username, "The two PINs are different."), 400)
        owned = STATE.store.credential_count(user)
        if owned >= MAX_CREDENTIALS_PER_USER:
            return html(render_authorize(request, txn, username,
                                         f"You already have {owned} credentials, the maximum on this demo."), 400)
        pin_hash = hash_secret(pin)
        if t.details:
            # What the user approved: the requested policy, with the subject from the confirmed account.
            d = json.loads(json.dumps(t.details[0]))
            d["credentialCreationRequest"]["subjectData"] = {"given_name": record["given_name"],
                                                              "family_name": record["family_name"]}
            approved = [d]

    STATE.authz.pop(txn)
    code = secrets.token_urlsafe(32)
    STATE.codes[code] = AuthCode(t.client_id, t.redirect_uri, t.redirect_uri_given, user, t.scope, approved,
                                 t.challenge, t.method, time.time() + AUTH_CODE_TTL, pin_hash)
    print(f"  [oauth2] {user} approved scope {t.scope} for {t.client_id}", flush=True)
    return RedirectResponse(with_query(t.redirect_uri, {"code": code, "state": t.state}), status_code=302)


def client_auth(request: Request, form) -> str:
    """Authenticate the confidential client (HTTP Basic or client_secret in the body)."""
    header = request.headers.get("authorization", "")
    if header.startswith("Basic "):
        try:
            cid, secret = base64.b64decode(header[6:]).decode().split(":", 1)
            cid, secret = unquote(cid), unquote(secret)  # RFC 6749 2.3.1 form-encodes both
        except (ValueError, binascii.Error, UnicodeDecodeError):
            raise CSCError(401, "invalid_request", "Malformed client authentication")
    else:
        cid, secret = form.get("client_id"), form.get("client_secret")
    if not cid:
        raise bad("Missing parameter client_id")
    client = OAUTH_CLIENTS.get(cid)
    if client is None:
        raise bad("Invalid parameter client_id")
    if not secret:
        raise CSCError(401, "invalid_request", "Client authorization required")
    if not secrets.compare_digest(str(secret), client["secret"]):
        raise bad("Invalid parameter client_secret")
    return cid


def pkce_ok(verifier: str, challenge: str, method: str) -> bool:
    if method == "S256":
        verifier = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    return secrets.compare_digest(verifier, challenge)


@app.post("/oauth2/token")
async def oauth2_token(request: Request):
    form = await request.form()
    client_id = client_auth(request, form)
    grant = form.get("grant_type")
    if not grant:
        raise bad("Missing parameter grant_type")
    if grant != "authorization_code":
        raise bad("Invalid parameter grant_type")
    code = form.get("code")
    if not code:
        raise bad("Missing parameter code")

    ac = STATE.codes.get(code)
    if ac is None or ac.client_id != client_id:
        raise bad("Invalid parameter code", "invalid_grant")
    if ac.used or ac.expires_at < time.time():
        if ac.used and ac.token:  # a replayed code revokes what it produced (OAuth Security BCP)
            STATE.access_tokens.pop(ac.token, None)
        raise bad("Authorization code is invalid or expired", "invalid_grant")
    if ac.redirect_uri_given and form.get("redirect_uri") != ac.redirect_uri:
        raise bad("redirect_uri parameter does not match redirect_uri parameter of authorization request",
                  "invalid_grant")
    verifier = form.get("code_verifier")
    if not verifier:
        raise bad("Missing parameter code_verifier")
    if not pkce_ok(str(verifier), ac.challenge, ac.method):
        raise bad("PKCE verification failed", "invalid_grant")
    if ac.details is not None and not form.get("authorization_details"):
        raise bad("Missing parameter authorization_details")

    ac.used = True
    ttl = CREATION_TOKEN_TTL if ac.scope == "credential-creation" else ACCESS_TOKEN_TTL
    token = secrets.token_urlsafe(32)
    STATE.access_tokens[token] = Token(ac.user, time.time() + ttl, ac.scope, client_id, ac.details, ac.pin_hash)
    ac.token = token
    out = {"access_token": token, "token_type": "Bearer", "expires_in": ttl}
    if ac.details is not None:
        out["authorization_details"] = ac.details
    return JSONResponse(out, headers={"Cache-Control": "no-store", "Pragma": "no-cache"})


@app.post("/oauth2/revoke")
async def oauth2_revoke(request: Request):
    form = await request.form()
    client_id = client_auth(request, form)
    token = form.get("token")
    if not token:
        raise bad("Missing parameter token")
    if form.get("token_type_hint") not in (None, "access_token", "refresh_token"):
        raise bad("Invalid parameter token_type_hint")
    tok = STATE.access_tokens.get(token)
    if tok is not None and tok.client_id in (None, client_id):
        STATE.access_tokens.pop(token)
    return Response(status_code=204)  # unknown tokens are not an error (RFC 7009)


# --------------------------------------------------------------------------- #
@app.get("/logo.png")
async def logo():
    png = base64.b64decode(
        "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg=="
    )
    return Response(content=png, media_type="image/png")


if LEAK_OTP:
    @app.get("/demo/otp/{credential_id}")
    async def demo_otp(credential_id: str):
        """NOT part of CSC: lets scripted demos read the 'SMS'."""
        sent = STATE.otps.get(credential_id)
        if not sent:
            raise CSCError(404, "invalid_request", "No OTP pending for this credential")
        return {"otp": sent[0]}


if __name__ == "__main__":
    import uvicorn

    port = int(os.environ.get("CSC_PORT", "8080"))
    host = os.environ.get("CSC_HOST", "127.0.0.1")
    print(f"CSC demo RSSP on http://{host}:{port}{BASE}/  (Swagger UI: /docs)")
    print(f"Demo user: alice / {os.environ.get('DEMO_USER_PASSWORD', 'alice-password')}   "
          f"email: {STATE.store.user('alice')['email']}")
    print(f"Database: {STATE.store.path} ({STATE.store.user_count()} accounts)")
    print(f"Sign-up page: {PUBLIC_URL or f'http://{host}:{port}'}/account/signup")
    print(f"OAuth client: {', '.join(OAUTH_CLIENTS)} → {', '.join(next(iter(OAUTH_CLIENTS.values()))['redirect_uris'])}")
    if PUBLIC_URL.startswith("https://") and any(c["secret"] == "csc-signer-demo-secret"
                                                  for c in OAUTH_CLIENTS.values()):
        print("WARNING: set CSC_OAUTH_CLIENT_SECRET; the default secret is published in the repository")
    print(f"Email delivery: {mailer.mode()}" + ("" if mailer.mode() == "smtp" else
          "  (set SMTP_HOST etc. in server/.env to send real emails)"))
    uvicorn.run(app, host=host, port=port, log_level="warning", proxy_headers=True)
