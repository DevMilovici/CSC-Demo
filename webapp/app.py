"""CSC Signer: a web-based signature application for the CSC API v2.2.

Architecture:

    browser (static/index.html + app.js)
        │  JSON over /api/*
        ▼
    this backend ("signature application" in CSC terms)
        │  CSC API v2: POST + JSON, Bearer tokens
        ▼
    remote signing service provider (server/csc_server.py)

The backend prepares the PDF and computes the hash with pyHanko's *interrupted
signing* (so we can stop and wait while the user reads their email), calls the
CSC API and finally embeds the returned signature value as PAdES. Every CSC
request/response is returned to the browser so the UI can show the "wire log".

It can also ask the provider for a NEW credential with the OAuth 2.0 flow of
the spec (section 8.1.2 + 11.4): redirect to oauth2/authorize with a
"credential-creation" authorization_details (PKCE + state), the user logs in and
picks the signing PIN on the provider's page, the provider redirects back to
/oauth/callback, and this backend exchanges the code at oauth2/token and calls
credentials/create with that token.

Run:  python webapp/app.py      (http://127.0.0.1:8000)
"""

from __future__ import annotations

import base64
import hashlib
import io
import os
import secrets
import json
import time
from dataclasses import dataclass, field
from html import escape
from pathlib import Path
from urllib.parse import urlencode

import httpx
from asn1crypto import algos
from asn1crypto import x509 as ax509
from fastapi import FastAPI, File, Form, Request, UploadFile
from fastapi.responses import JSONResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign import fields, signers
from pyhanko.sign.signers.pdf_signer import PdfTBSDocument
from pyhanko.sign.validation import async_validate_pdf_signature
from pyhanko_certvalidator import ValidationContext
from pyhanko_certvalidator.registry import SimpleCertificateStore

STATIC = Path(__file__).resolve().parent / "static"
DEFAULT_CSC = os.environ.get("CSC_SERVER", "http://127.0.0.1:8080").rstrip("/")
# On a public host, lock the app to DEFAULT_CSC. Otherwise this backend POSTs to any URL a visitor
# types in and shows the response: a server-side request forgery into the host's internal network.
SERVER_LOCKED = os.environ.get("CSC_SERVER_LOCKED", "0").lower() in ("1", "true", "yes")
# "user:password" prefilled in step 1 for the built-in demo account; set it empty to prefill nothing.
DEMO_USERNAME, _, DEMO_PASSWORD = os.environ.get("WEBAPP_DEMO_LOGIN", "alice:alice-password").partition(":")
OID_SHA256 = "2.16.840.1.101.3.4.2.1"
OID_SHA256_RSA = "1.2.840.113549.1.1.11"
MAX_PDF_BYTES = 10 * 1024 * 1024
SECRET_KEYS = {"value", "password", "SAD", "access_token", "refresh_token", "code", "code_verifier",
               "client_secret"}

# Where the browser reaches this app; the OAuth redirect_uri is derived from it and must be
# registered at the provider (CSC_OAUTH_REDIRECT_URIS on the server).
PORT = int(os.environ.get("WEBAPP_PORT", "8000"))
PUBLIC_URL = os.environ.get("WEBAPP_PUBLIC_URL", f"http://127.0.0.1:{PORT}").rstrip("/")
REDIRECT_URI = f"{PUBLIC_URL}/oauth/callback"
OAUTH_CLIENT_ID = os.environ.get("OAUTH_CLIENT_ID", "csc-signer")
OAUTH_CLIENT_SECRET = os.environ.get("OAUTH_CLIENT_SECRET", "csc-signer-demo-secret")
OAUTH_FLOW_TTL = 600
RAR_CREATION = "https://cloudsignatureconsortium.org/2025/credential-creation"

# Certificate policies this app knows how to ask for (Note 37: the provider documents them).
POLICY_CHOICES = {
    "qes": {"oid": "0.4.0.194112.1.2", "authData": [{"id": "PIN"}, {"id": "EMAIL_OTP"}]},
    "adv": {"oid": "0.4.0.2042.1.1", "authData": [{"id": "PIN"}]},
}


# --------------------------------------------------------------------------- #
# Per-browser session state (in memory; demo only)
# --------------------------------------------------------------------------- #
@dataclass
class Session:
    server: str = DEFAULT_CSC
    token: str | None = None
    username: str = ""
    info: dict = field(default_factory=dict)
    credentials: dict[str, dict] = field(default_factory=dict)
    cred_list: list[dict] = field(default_factory=list)  # summaries shown in step 2
    oauth: dict | None = None  # pending credential-creation flow: state, PKCE verifier, request
    pending_log: list = field(default_factory=list)  # wire log produced during the OAuth redirect
    notice: dict | None = None  # message to show after the redirect back
    credential_id: str | None = None
    filename: str = ""
    # interrupted-signing state from pyHanko
    prep_digest: object = None
    post_sign: object = None
    output: io.BytesIO | None = None
    signed_attrs: object = None
    tbs_hash: bytes | None = None
    signed_pdf: bytes | None = None


SESSIONS: dict[str, Session] = {}
app = FastAPI(title="CSC Signer web app")


class AppError(Exception):
    def __init__(self, message: str, log: list | None = None, status: int = 400):
        self.message, self.log, self.status = message, log or [], status


@app.exception_handler(AppError)
async def _app_error(_: Request, exc: AppError):
    return JSONResponse(status_code=exc.status, content={"error": exc.message, "log": exc.log})


def session_of(request: Request) -> tuple[str, Session]:
    sid = request.cookies.get("csc_sid")
    if not sid or sid not in SESSIONS:
        sid = secrets.token_urlsafe(24)
        SESSIONS[sid] = Session()
    return sid, SESSIONS[sid]


def with_cookie(sid: str, r: Response) -> Response:
    # Lax, not Strict: the cookie must come back on the top-level redirect from the provider.
    r.set_cookie("csc_sid", sid, httponly=True, samesite="lax", secure=PUBLIC_URL.startswith("https://"))
    return r


def reply(sid: str, payload: dict) -> JSONResponse:
    return with_cookie(sid, JSONResponse(payload))


# --------------------------------------------------------------------------- #
# CSC calls, recorded for the wire log
# --------------------------------------------------------------------------- #
def redact(obj, limit=64):
    if isinstance(obj, dict):
        return {k: ("•••• (hidden)" if k in SECRET_KEYS else redact(v, limit)) for k, v in obj.items()}
    if isinstance(obj, list):
        return [redact(v, limit) for v in obj]
    if isinstance(obj, str) and len(obj) > limit:
        return obj[: limit - 1] + "…"
    return obj


async def csc(s: Session, log: list, method: str, payload: dict | None = None, *, basic=None, step: str = "",
              token: str | None = None):
    headers = {"Content-Type": "application/json"}
    shown_auth = None
    token = token or s.token
    if basic:
        headers["Authorization"] = "Basic " + base64.b64encode(f"{basic[0]}:{basic[1]}".encode()).decode()
        shown_auth = "Basic •••• (username:password)"
    elif token:
        headers["Authorization"] = "Bearer " + token
        shown_auth = "Bearer " + token[:8] + "…"
    payload = payload or {}
    t0 = time.perf_counter()
    try:
        async with httpx.AsyncClient(timeout=40) as http:
            r = await http.post(f"{s.server.rstrip('/')}/csc/v2/{method}", json=payload, headers=headers)
    except httpx.HTTPError as exc:
        log.append({"method": method, "step": step, "status": 0, "ms": 0, "auth": shown_auth,
                    "request": redact(payload), "response": {"error": str(exc)}})
        raise AppError(f"Cannot reach the CSC server at {s.server}", log, 502)
    data = r.json() if r.content else None
    log.append({"method": method, "step": step, "status": r.status_code,
                "ms": round((time.perf_counter() - t0) * 1000), "auth": shown_auth,
                "request": redact(payload), "response": redact(data) if data is not None else None})
    if r.status_code >= 300:
        msg = (data or {}).get("error_description") or (data or {}).get("error") or f"HTTP {r.status_code}"
        raise AppError(msg, log, 400 if r.status_code < 500 else 502)
    return data


async def oauth_token(s: Session, log: list, form: dict, step: str) -> dict:
    """POST oauth2/token (form-encoded, client secret via HTTP Basic as RFC 6749 recommends)."""
    url = s.info["oauth2"].rstrip("/") + "/oauth2/token"
    auth = base64.b64encode(f"{OAUTH_CLIENT_ID}:{OAUTH_CLIENT_SECRET}".encode()).decode()
    shown = {k: (json.loads(v) if k == "authorization_details" else v) for k, v in form.items()}
    t0 = time.perf_counter()
    try:
        async with httpx.AsyncClient(timeout=40) as http:
            r = await http.post(url, data=form, headers={"Authorization": f"Basic {auth}"})
    except httpx.HTTPError as exc:
        log.append({"method": "oauth2/token", "http": "POST /oauth2/token", "step": step, "status": 0, "ms": 0,
                    "auth": "Basic •••• (client_id:client_secret)", "request": redact(shown),
                    "response": {"error": str(exc)}})
        raise AppError("Cannot reach the provider's token endpoint", log, 502)
    data = r.json() if r.content else None
    log.append({"method": "oauth2/token", "http": "POST /oauth2/token", "step": step, "status": r.status_code,
                "ms": round((time.perf_counter() - t0) * 1000), "auth": "Basic •••• (client_id:client_secret)",
                "request": redact(shown), "response": redact(data) if data is not None else None})
    if r.status_code >= 300:
        msg = (data or {}).get("error_description") or (data or {}).get("error") or f"HTTP {r.status_code}"
        raise AppError(msg, log, 400 if r.status_code < 500 else 502)
    return data


def require(s: Session, what: str):
    if what == "login" and not s.token:
        raise AppError("Connect to a CSC server first")
    if what == "credential" and (not s.credential_id or s.credential_id not in s.credentials):
        raise AppError("Choose a credential first")
    if what == "document" and s.tbs_hash is None:
        raise AppError("Upload a PDF first")


# --------------------------------------------------------------------------- #
# API used by the browser
# --------------------------------------------------------------------------- #
@app.post("/api/connect")
async def api_connect(request: Request):
    sid, s = session_of(request)
    body = await request.json()
    server = DEFAULT_CSC if SERVER_LOCKED else (body.get("server") or DEFAULT_CSC).strip()
    SESSIONS[sid] = s = Session(server=server)
    log: list = []
    s.info = await csc(s, log, "info", step="Discover the service")
    login = await csc(s, log, "auth/login", {"rememberMe": False},
                      basic=(body.get("username", ""), body.get("password", "")),
                      step="Service authorization")
    s.token = login["access_token"]
    s.username = body.get("username", "")
    await load_credentials(s, log)
    return reply(sid, {**connection(s), "log": log})


def connection(s: Session) -> dict:
    methods = s.info.get("methods", [])
    return {"service": {k: s.info.get(k) for k in ("name", "specs", "description", "region", "methods")},
            "username": s.username, "credentials": s.cred_list,
            "canCreate": "credentials/create" in methods and bool(s.info.get("oauth2"))}


async def load_credentials(s: Session, log: list) -> None:
    ids = (await csc(s, log, "credentials/list", step="Find credentials"))["credentialIDs"]
    s.credentials, s.cred_list = {}, []
    for cid in ids:
        info = await csc(s, log, "credentials/info", {"credentialID": cid, "certificates": "chain",
                                                      "certInfo": True, "authInfo": True},
                         step="Learn how to unlock it")
        s.credentials[cid] = info
        objs = info["auth"].get("objects", [])
        s.cred_list.append({
            "id": cid, "description": info.get("description", ""), "scal": info.get("SCAL", "1"),
            "expression": info["auth"].get("expression", ""), "multisign": info.get("multisign"),
            "subject": info["cert"].get("subjectDN", ""), "issuer": info["cert"].get("issuerDN", ""),
            "validTo": info["cert"].get("validTo", ""),
            "needsCode": any(o["type"].startswith("ChallengeResponse") for o in objs),
            "codeHint": next((o.get("description", "") for o in objs if o["id"] == "EMAIL_OTP"), ""),
        })


@app.get("/api/state")
async def api_state(request: Request):
    """Restore the UI after the round trip through the provider's consent page."""
    sid, s = session_of(request)
    out = {"connected": bool(s.token), "log": s.pending_log, "notice": s.notice}
    if s.token:
        out.update(connection(s))
    s.pending_log, s.notice = [], None
    return reply(sid, out)


# --------------------------------------------------------------------------- #
# New credential: OAuth 2.0 Authorization Code flow + credentials/create
# --------------------------------------------------------------------------- #
@app.post("/api/credentials/request")
async def api_request_credential(request: Request):
    sid, s = session_of(request)
    require(s, "login")
    body = await request.json()
    choice = POLICY_CHOICES.get(body.get("policy"))
    if choice is None:
        raise AppError("Choose a kind of credential")
    if not s.info.get("oauth2") or "credentials/create" not in s.info.get("methods", []):
        raise AppError("This provider does not offer credentials/create with OAuth 2.0")

    verifier = secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    params = {"response_type": "code", "client_id": OAUTH_CLIENT_ID, "redirect_uri": REDIRECT_URI,
              "code_challenge": challenge, "code_challenge_method": "S256", "state": secrets.token_urlsafe(16)}
    details = None
    if s.info.get("supportsRar"):
        # No subjectData: the provider takes the name from the user's confirmed account.
        details = json.dumps([{"type": RAR_CREATION, "credentialCreationRequest": {"certificatePolicy": choice["oid"]}}])
        params["authorization_details"] = details
    else:
        params["scope"] = "credential-creation"
    s.oauth = {"params": params, "verifier": verifier, "details": details, "choice": choice,
               "expires_at": time.time() + OAUTH_FLOW_TTL}
    return reply(sid, {"redirect": s.info["oauth2"].rstrip("/") + "/oauth2/authorize?" + urlencode(params),
                       "log": []})


@app.get("/oauth/callback")
async def oauth_callback(request: Request):
    sid, s = session_of(request)
    q = request.query_params
    pending, s.oauth = s.oauth, None
    done = with_cookie(sid, RedirectResponse("/", status_code=303))
    if (not pending or pending["expires_at"] < time.time()
            or not secrets.compare_digest(q.get("state", ""), pending["params"]["state"])):
        s.notice = {"kind": "error", "text": "That answer from the provider doesn't match a request from this "
                                             "browser (or it took too long). Start again."}
        return done

    shown = {k: (json.loads(v) if k == "authorization_details" else v) for k, v in pending["params"].items()}
    response = {k: q[k] for k in ("code", "state", "error", "error_description") if k in q}
    log = [{"method": "oauth2/authorize", "http": "GET /oauth2/authorize", "step": "You signed in at the provider",
            "status": 302, "ms": 0, "auth": None, "request": redact(shown), "response": redact(response)}]
    if "error" in q or "code" not in q:
        log[0]["status"] = 400
        s.pending_log = log
        s.notice = {"kind": "error", "text": "No credential was created: " +
                    (q.get("error_description") or q.get("error") or "the provider returned no code")}
        return done

    try:
        form = {"grant_type": "authorization_code", "code": q["code"], "redirect_uri": REDIRECT_URI,
                "code_verifier": pending["verifier"]}
        if pending["details"]:
            form["authorization_details"] = pending["details"]
        tok = await oauth_token(s, log, form, step="Code → creation token")
        created = await csc(s, log, "credentials/create", {
            "credentialCreationRequest": {"certificatePolicy": pending["choice"]["oid"]},
            "authData": pending["choice"]["authData"], "credentialInfo": True, "certificates": "chain",
            "certInfo": True}, token=tok["access_token"], step="Create the credential")
        await load_credentials(s, log)
        cid = created["credentialID"]
        if cid in s.credentials:
            s.notice = {"kind": "ok", "text": f"New credential created: {created.get('description', cid)} "
                                              f"for {created['cert'].get('subjectDN', '')}."}
        else:
            s.notice = {"kind": "warn", "text": f"Credential {cid} was created for the account you signed in "
                        "with at the provider, which isn't the one connected here. Connect as that user to use it."}
    except AppError as exc:
        log = exc.log
        s.notice = {"kind": "error", "text": f"No credential was created: {exc.message}"}
    s.pending_log = log
    return done


@app.post("/api/document")
async def api_document(request: Request, file: UploadFile = File(...), credentialID: str = Form(...)):
    sid, s = session_of(request)
    require(s, "login")
    if credentialID not in s.credentials:
        raise AppError("Unknown credential")
    s.credential_id = credentialID
    pdf = await file.read()
    if len(pdf) > MAX_PDF_BYTES:
        raise AppError("PDF is larger than 10 MB")
    if not pdf.startswith(b"%PDF"):
        raise AppError("That file is not a PDF")

    info = s.credentials[credentialID]
    chain = [base64.b64decode(c) for c in info["cert"]["certificates"]]
    signing_cert = ax509.Certificate.load(chain[0])
    registry = SimpleCertificateStore.from_certs([ax509.Certificate.load(c) for c in chain[1:]])
    mech = algos.SignedDigestAlgorithm({"algorithm": "sha256_rsa"})
    # placeholder signer: reserves room for a signature of the key's size
    placeholder = signers.ExternalSigner(signing_cert, registry, signature_value=info["key"]["len"] // 8,
                                         signature_mechanism=mech)
    meta = signers.PdfSignatureMetadata(field_name=f"Signature{secrets.randbelow(10**6)}", md_algorithm="sha256",
                                        subfilter=fields.SigSeedSubFilter.PADES,
                                        reason="Signed remotely via the CSC API", location="CSC Signer web app")
    try:
        writer = IncrementalPdfFileWriter(io.BytesIO(pdf))
        pdf_signer = signers.PdfSigner(meta, signer=placeholder)
        output = io.BytesIO()
        prep, tbs, output = await pdf_signer.async_digest_doc_for_signing(writer, output=output)
        signed_attrs = await placeholder.signed_attrs(prep.document_digest, "sha256", use_pades=True)
    except Exception as exc:  # malformed / encrypted PDFs
        raise AppError(f"Could not prepare this PDF for signing: {exc}")

    s.filename = Path(file.filename or "document.pdf").stem
    s.prep_digest, s.post_sign, s.output, s.signed_attrs = prep, tbs.post_sign_instructions, output, signed_attrs
    s.tbs_hash = hashlib.sha256(signed_attrs.dump()).digest()
    s.signed_pdf = None
    return reply(sid, {
        "filename": file.filename, "size": len(pdf),
        "documentDigest": base64.b64encode(prep.document_digest).decode(),
        "hash": base64.b64encode(s.tbs_hash).decode(),
        "log": [],
    })


@app.post("/api/challenge")
async def api_challenge(request: Request):
    sid, s = session_of(request)
    require(s, "login")
    require(s, "credential")
    log: list = []
    await csc(s, log, "credentials/getChallenge", {"credentialID": s.credential_id, "authObjectID": "EMAIL_OTP"},
              step="Email me a code")
    return reply(sid, {"sent": True, "log": log})


@app.post("/api/sign")
async def api_sign(request: Request):
    sid, s = session_of(request)
    require(s, "login")
    require(s, "credential")
    require(s, "document")
    body = await request.json()
    pin, code = str(body.get("pin", "")), str(body.get("code", ""))
    info = s.credentials[s.credential_id]
    auth = [{"id": "PIN", "value": pin}]
    if any(o["id"] == "EMAIL_OTP" for o in info["auth"].get("objects", [])):
        auth.append({"id": "EMAIL_OTP", "value": code})
    h = base64.b64encode(s.tbs_hash).decode()
    log: list = []

    sad = (await csc(s, log, "credentials/authorize", {
        "credentialID": s.credential_id, "numSignatures": 1, "hashes": [h],
        "hashAlgorithmOID": OID_SHA256, "authData": auth,
        "description": f"Sign {s.filename}.pdf"}, step="Consent → SAD"))["SAD"]

    sig_b64 = (await csc(s, log, "signatures/signHash", {
        "credentialID": s.credential_id, "SAD": sad, "hashes": [h],
        "hashAlgorithmOID": OID_SHA256, "signAlgo": OID_SHA256_RSA}, step="HSM signs the hash"))["signatures"][0]

    # finish the interrupted signature: embed the value into the CMS and the PDF
    chain = [base64.b64decode(c) for c in info["cert"]["certificates"]]
    finisher = signers.ExternalSigner(
        ax509.Certificate.load(chain[0]),
        SimpleCertificateStore.from_certs([ax509.Certificate.load(c) for c in chain[1:]]),
        signature_value=base64.b64decode(sig_b64),
        signature_mechanism=algos.SignedDigestAlgorithm({"algorithm": "sha256_rsa"}),
    )
    cms = await finisher.async_sign_prescribed_attributes("sha256", signed_attrs=s.signed_attrs)
    await PdfTBSDocument.async_finish_signing(s.output, s.prep_digest, cms, post_sign_instr=s.post_sign)
    s.signed_pdf = s.output.getvalue()
    s.tbs_hash = None  # one document = one signature

    validation = await validate(s.signed_pdf, chain[-1])
    return reply(sid, {"signature": sig_b64[:48] + "…", "size": len(s.signed_pdf),
                       "download": "/api/download", "validation": validation, "log": log})


async def validate(pdf: bytes, root_der: bytes) -> dict:
    vc = ValidationContext(trust_roots=[ax509.Certificate.load(root_der)], allow_fetching=False,
                           revocation_mode="soft-fail")
    sig = PdfFileReader(io.BytesIO(pdf)).embedded_signatures[-1]
    st = await async_validate_pdf_signature(sig, vc)
    return {"intact": st.intact, "valid": st.valid, "trusted": st.trusted,
            "signer": st.signing_cert.subject.human_friendly,
            "signingTime": st.signer_reported_dt.isoformat() if st.signer_reported_dt else None,
            "trustRoot": ax509.Certificate.load(root_der).subject.human_friendly}


@app.get("/api/download")
async def api_download(request: Request):
    _, s = session_of(request)
    if not s.signed_pdf:
        raise AppError("Nothing signed yet", status=404)
    return Response(s.signed_pdf, media_type="application/pdf",
                    headers={"Content-Disposition": f'attachment; filename="{s.filename}-signed.pdf"'})


NO_CACHE = {"Cache-Control": "no-cache"}  # always revalidate, so an updated app.js/style.css is never stale


def asset_url(name: str) -> str:
    """/static/<name>?v=<content hash>: a changed file gets a new URL, which no cache can hold."""
    digest = hashlib.sha256((STATIC / name).read_bytes()).hexdigest()[:12]
    return f"/static/{name}?v={digest}"


@app.get("/")
async def index():
    page = (STATIC / "index.html").read_text(encoding="utf-8")
    for name in ("style.css", "app.js"):
        page = page.replace(f'"/static/{name}"', f'"{asset_url(name)}"')
    for marker, value in {"{{CSC_SERVER}}": escape(DEFAULT_CSC), "{{DEMO_USERNAME}}": escape(DEMO_USERNAME),
                          "{{DEMO_PASSWORD}}": escape(DEMO_PASSWORD),
                          "{{SERVER_LOCK}}": " readonly" if SERVER_LOCKED else ""}.items():
        page = page.replace(marker, value)
    return Response(page, media_type="text/html; charset=utf-8", headers=NO_CACHE)


@app.middleware("http")
async def revalidate_static(request: Request, call_next):
    response = await call_next(request)
    if request.url.path.startswith("/static/"):
        response.headers.update(NO_CACHE)
    return response


app.mount("/static", StaticFiles(directory=STATIC), name="static")


if __name__ == "__main__":
    import uvicorn

    host = os.environ.get("WEBAPP_HOST", "127.0.0.1")
    print(f"CSC Signer web app on http://{host}:{PORT}  (CSC server: {DEFAULT_CSC}"
          f"{', locked' if SERVER_LOCKED else ''})")
    print(f"OAuth client {OAUTH_CLIENT_ID}, redirect_uri {REDIRECT_URI}")
    uvicorn.run(app, host=host, port=PORT, log_level="warning", proxy_headers=True)
