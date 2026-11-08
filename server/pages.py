"""HTML pages served by the provider itself (not part of the CSC API).

* account sign-up and email confirmation: the spec leaves user enrollment out of scope
* the OAuth 2.0 login + consent screen behind oauth2/authorize: the spec gives the
  authorization server "full screen control" here (Note 18), so the signing PIN for a
  new credential is chosen on this page and never passes through the signature app.

Everything interpolated into the HTML goes through esc().
"""

from __future__ import annotations

from html import escape

CSS = """
:root { --ink:#15171E; --paper:#F5F3EE; --card:#FFFFFF; --line:#E2DED5; --text:#1B1D24; --muted:#5B606B;
  --accent:#C4471D; --accent-soft:#FBE6DC; --teal:#0E6B58; --teal-soft:#DCEFE8; --red:#B42318; --red-soft:#FDE8E6;
  --sans: Inter, system-ui, -apple-system, "Segoe UI", sans-serif; --head: "Space Grotesk", var(--sans);
  --mono: "JetBrains Mono", ui-monospace, Menlo, monospace; }
* { box-sizing: border-box; }
body { margin:0; background:var(--paper); color:var(--text); font:15px/1.5 var(--sans); }
.top { padding:14px 24px; background:var(--ink); color:#F2EFE8; font:600 17px var(--head); }
.top span { color:#F08A5D; }
main { max-width:460px; margin:32px auto; padding:0 16px; }
.card { background:var(--card); border:1px solid var(--line); border-radius:12px; padding:24px; }
h1 { font:600 22px/1.25 var(--head); margin:0 0 6px; }
p { margin:8px 0; } .muted { color:var(--muted); font-size:14px; }
label { display:block; font-size:13px; font-weight:500; color:var(--muted); margin-top:14px; }
input { display:block; width:100%; margin-top:5px; padding:10px 12px; font:15px var(--sans); color:var(--text);
  border:1px solid var(--line); border-radius:8px; background:#FCFBF8; }
input:focus { outline:2px solid var(--accent-soft); border-color:var(--accent); }
.row { display:grid; grid-template-columns:1fr 1fr; gap:12px; }
.actions { display:flex; gap:10px; margin-top:22px; flex-wrap:wrap; }
button, .button { font:600 15px var(--sans); padding:10px 18px; border-radius:8px; border:1px solid var(--line);
  background:#fff; color:var(--text); cursor:pointer; text-decoration:none; display:inline-block; }
button.primary, .button.primary { background:var(--accent); border-color:var(--accent); color:#fff; }
.error { background:var(--red-soft); color:var(--red); padding:10px 12px; border-radius:8px; font-size:14px; margin-top:12px; }
.ok { background:var(--teal-soft); color:var(--teal); padding:10px 12px; border-radius:8px; font-size:14px; margin-top:12px; }
.ask { border:1px solid var(--line); border-radius:10px; padding:12px 14px; margin:14px 0 4px; background:#FCFBF8; }
.ask dt { font-size:12px; color:var(--muted); text-transform:uppercase; letter-spacing:.04em; margin-top:8px; }
.ask dt:first-child { margin-top:0; } .ask dd { margin:2px 0 0; }
code { font-family:var(--mono); font-size:.86em; background:#EEEBE4; padding:1px 5px; border-radius:4px; }
.foot { text-align:center; margin-top:16px; font-size:13px; color:var(--muted); }
a { color:var(--accent); }
@media (max-width:480px) { .row { grid-template-columns:1fr; } .card { padding:18px; } }
"""


def esc(value) -> str:
    return escape(str(value), quote=True)


def layout(title: str, body: str) -> str:
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>{esc(title)} · CSC Demo Trust Services</title><style>{CSS}</style></head>
<body><div class="top"><span>✦</span> CSC Demo Trust Services</div>
<main>{body}<p class="foot">Teaching demo of a remote signing service. Certificates have no legal effect.</p></main>
</body></html>"""


def _error(message: str | None) -> str:
    return f'<div class="error" role="alert">{esc(message)}</div>' if message else ""


# --------------------------------------------------------------------------- #
# Sign-up
# --------------------------------------------------------------------------- #
def signup(values: dict, next_url: str, error: str | None = None, min_password: int = 10) -> str:
    v = {k: esc(values.get(k, "")) for k in ("given_name", "family_name", "email")}
    return layout("Create an account", f"""<div class="card">
<h1>Create an account</h1>
<p class="muted">Your name goes into the signing certificates we issue, so use your real one. We'll email you a link to
confirm the address.</p>
{_error(error)}
<form method="post" action="/account/signup">
  <input type="hidden" name="next" value="{esc(next_url)}">
  <div class="row">
    <label>Given name<input name="given_name" value="{v['given_name']}" autocomplete="given-name" maxlength="64" required></label>
    <label>Family name<input name="family_name" value="{v['family_name']}" autocomplete="family-name" maxlength="64" required></label>
  </div>
  <label>Email (this is also your username)<input name="email" type="email" value="{v['email']}" autocomplete="email" maxlength="254" required></label>
  <label>Password (at least {min_password} characters)<input name="password" type="password" autocomplete="new-password" minlength="{min_password}" maxlength="128" required></label>
  <label>Repeat the password<input name="password2" type="password" autocomplete="new-password" minlength="{min_password}" maxlength="128" required></label>
  <div class="actions"><button class="primary" type="submit">Create account</button></div>
</form></div>""")


def signup_sent(masked_email: str, ttl_hours: int) -> str:
    return layout("Check your inbox", f"""<div class="card">
<h1>Check your inbox</h1>
<p>We sent a confirmation link to <b>{esc(masked_email)}</b>. Open it within {ttl_hours} hours to activate the account.</p>
<p class="muted">Nothing there? Look in the spam folder. You can sign up again with the same address to get a new link.</p>
</div>""")


def verified(email: str, next_url: str | None) -> str:
    action = (f'<div class="actions"><a class="button primary" href="{esc(next_url)}">Continue to sign in</a></div>'
              if next_url else '<p class="muted">Go back to the signing app and sign in with your email and password.</p>')
    return layout("Email confirmed", f"""<div class="card">
<h1>Email confirmed</h1>
<div class="ok">Your account <b>{esc(email)}</b> is active.</div>
{action}</div>""")


def message(title: str, text: str) -> str:
    return layout(title, f'<div class="card"><h1>{esc(title)}</h1><p>{esc(text)}</p></div>')


# --------------------------------------------------------------------------- #
# OAuth 2.0 login + consent
# --------------------------------------------------------------------------- #
def authorize(*, txn: str, client_name: str, scope: str, policy: dict | None, policy_oid: str | None,
              signup_url: str, username: str = "", error: str | None = None) -> str:
    if scope == "credential-creation":
        if policy:
            what = f"{esc(policy['label'])} <code>{esc(policy_oid)}</code>"
            unlock = esc(policy["unlock"])
        else:
            what = "A certificate policy chosen by the app when it creates the credential"
            unlock = "Your PIN, plus an emailed code for qualified signatures"
        asks = f"""<dl class="ask">
  <dt>Wants to</dt><dd>Create a new signing key and certificate in your name</dd>
  <dt>Certificate</dt><dd>{what}</dd>
  <dt>Name on the certificate</dt><dd>Taken from your confirmed account, not from the app</dd>
  <dt>Each signature will need</dt><dd>{unlock}</dd>
</dl>"""
        pin_fields = """<div class="row">
    <label>Choose a signing PIN<input name="pin" type="password" inputmode="numeric" pattern="[0-9]{4,8}" minlength="4" maxlength="8" autocomplete="new-password" required></label>
    <label>Repeat the PIN<input name="pin2" type="password" inputmode="numeric" pattern="[0-9]{4,8}" minlength="4" maxlength="8" autocomplete="new-password" required></label>
  </div><p class="muted">4 to 8 digits. You'll type it every time you sign. Only this provider ever sees it.</p>"""
    else:
        asks = """<dl class="ask"><dt>Wants to</dt><dd>See your signing credentials and request signatures with them</dd></dl>"""
        pin_fields = ""
    return layout("Authorize", f"""<div class="card">
<h1>Sign in to continue</h1>
<p><b>{esc(client_name)}</b> is asking for access to your account.</p>
{asks}
{_error(error)}
<form method="post" action="/oauth2/authorize">
  <input type="hidden" name="txn" value="{esc(txn)}">
  <label>Email or username<input name="username" value="{esc(username)}" autocomplete="username" required></label>
  <label>Password<input name="password" type="password" autocomplete="current-password" required></label>
  {pin_fields}
  <div class="actions"><button class="primary" type="submit" name="decision" value="approve">Approve</button>
  <button type="submit" name="decision" value="deny" formnovalidate>Deny</button></div>
</form>
<p class="muted" style="margin-top:16px">No account yet? <a href="{esc(signup_url)}">Create one</a>, then come back here.</p>
</div>""")
