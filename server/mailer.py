"""Send the one-time signing code and the sign-up confirmation link by email over SMTP.

Configured with environment variables (or server/.env):

    SMTP_HOST       e.g. smtp.gmail.com     (unset = console mode: print instead of sending)
    SMTP_PORT       587 for STARTTLS, 465 for SSL, 25/1025 for plain
    SMTP_SECURITY   starttls | ssl | none   (default: starttls)
    SMTP_USERNAME   login for the SMTP server (often your email address)
    SMTP_PASSWORD   password / app password
    SMTP_FROM       From header, e.g. "CSC Demo <you@gmail.com>" (default: SMTP_USERNAME)
"""

from __future__ import annotations

import html
import os
import smtplib
import ssl
from email.message import EmailMessage
from email.utils import make_msgid


class MailError(Exception):
    pass


def mask(address: str) -> str:
    """alice.smith@example.com -> a*********@example.com"""
    local, _, domain = address.partition("@")
    if not domain:
        return "***"
    return (local[:1] + "*" * max(len(local) - 1, 3)) + "@" + domain


def mode() -> str:
    return "smtp" if os.environ.get("SMTP_HOST") else "console"


def _build(to: str, code: str, credential_label: str, ttl_minutes: int, sender: str) -> EmailMessage:
    msg = EmailMessage()
    msg["Subject"] = f"Your signing code: {code}"
    msg["From"] = sender
    msg["To"] = to
    msg["Message-ID"] = make_msgid(domain="csc-demo.local")
    msg.set_content(
        f"Someone (hopefully you) asked to sign with your credential:\n"
        f"  {credential_label}\n\n"
        f"Your one-time signing code is: {code}\n\n"
        f"It expires in {ttl_minutes} minutes and can be used once.\n"
        f"If you did not request this, ignore this email; nothing will be signed without it.\n\n"
        f"CSC Demo Trust Services (demo only, no legal effect)"
    )
    msg.add_alternative(
        f"""<!doctype html><html><body style="margin:0;background:#F5F3EE;font-family:Arial,Helvetica,sans-serif;color:#1B1D24">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0"><tr><td align="center" style="padding:32px 12px">
<table role="presentation" width="480" cellpadding="0" cellspacing="0" style="background:#ffffff;border-radius:12px;border:1px solid #E2DED5">
<tr><td style="padding:28px 32px 8px;font-size:13px;color:#C4471D;font-weight:bold">CSC Demo Trust Services</td></tr>
<tr><td style="padding:0 32px;font-size:22px;font-weight:bold">Your signing code</td></tr>
<tr><td style="padding:12px 32px;font-size:15px;line-height:1.5;color:#3A3E4A">Someone (hopefully you) asked to sign with
<b>{credential_label}</b>. Enter this code in the signing app:</td></tr>
<tr><td align="center" style="padding:12px 32px 20px"><div style="display:inline-block;background:#15171E;color:#F2EFE8;
font-family:'Courier New',monospace;font-size:34px;letter-spacing:8px;padding:14px 24px;border-radius:10px">{code}</div></td></tr>
<tr><td style="padding:0 32px 28px;font-size:13px;line-height:1.5;color:#5B606B">Expires in {ttl_minutes} minutes, single use.
If you didn't request this, ignore this email. Nothing can be signed without it.<br><br>Demo only, no legal effect.</td></tr>
</table></td></tr></table></body></html>""",
        subtype="html",
    )
    return msg


def _deliver(msg: EmailMessage, what: str) -> str:
    """Send over SMTP, or print in console mode. Raises MailError on SMTP failure."""
    host = os.environ.get("SMTP_HOST")
    port = int(os.environ.get("SMTP_PORT", "587"))
    security = os.environ.get("SMTP_SECURITY", "starttls").lower()
    user = os.environ.get("SMTP_USERNAME")
    password = os.environ.get("SMTP_PASSWORD")
    try:
        if security == "ssl":
            server = smtplib.SMTP_SSL(host, port, context=ssl.create_default_context(), timeout=20)
        else:
            server = smtplib.SMTP(host, port, timeout=20)
        with server:
            if security == "starttls":
                server.starttls(context=ssl.create_default_context())
            if user and password:
                server.login(user, password)
            server.send_message(msg)
    except (smtplib.SMTPException, OSError) as exc:
        raise MailError(f"{type(exc).__name__}: {exc}") from exc
    print(f"  [email] {what} sent to {mask(msg['To'])} via {host}:{port}", flush=True)
    return "smtp"


def _sender() -> str:
    return os.environ.get("SMTP_FROM") or os.environ.get("SMTP_USERNAME") or "csc-demo@localhost"


def send_code(to: str, code: str, credential_label: str, ttl_minutes: int) -> str:
    """Deliver the code. Returns "smtp" or "console". Raises MailError on SMTP failure."""
    if not os.environ.get("SMTP_HOST"):
        print(f"\n  [email: console mode, set SMTP_HOST to really send] to {to}: code {code}\n", flush=True)
        return "console"
    return _deliver(_build(to, code, credential_label, ttl_minutes, _sender()), "signing code")


def _build_verification(to: str, name: str, link: str, ttl_hours: int, sender: str) -> EmailMessage:
    msg = EmailMessage()
    msg["Subject"] = "Confirm your email for CSC Demo Trust Services"
    msg["From"] = sender
    msg["To"] = to
    msg["Message-ID"] = make_msgid(domain="csc-demo.local")
    msg.set_content(
        f"Hi {name},\n\n"
        f"Someone (hopefully you) created an account at CSC Demo Trust Services with this address.\n"
        f"Open this link to confirm it:\n\n  {link}\n\n"
        f"The link works once and expires in {ttl_hours} hours. If this wasn't you, ignore this email\n"
        f"and the account will be deleted.\n\n"
        f"CSC Demo Trust Services (demo only, no legal effect)"
    )
    safe_name, safe_link = html.escape(name), html.escape(link, quote=True)
    msg.add_alternative(
        f"""<!doctype html><html><body style="margin:0;background:#F5F3EE;font-family:Arial,Helvetica,sans-serif;color:#1B1D24">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0"><tr><td align="center" style="padding:32px 12px">
<table role="presentation" width="480" cellpadding="0" cellspacing="0" style="background:#ffffff;border-radius:12px;border:1px solid #E2DED5">
<tr><td style="padding:28px 32px 8px;font-size:13px;color:#C4471D;font-weight:bold">CSC Demo Trust Services</td></tr>
<tr><td style="padding:0 32px;font-size:22px;font-weight:bold">Confirm your email</td></tr>
<tr><td style="padding:12px 32px;font-size:15px;line-height:1.5;color:#3A3E4A">Hi {safe_name}, someone (hopefully you)
created an account with this address. Confirm it to start requesting signing credentials.</td></tr>
<tr><td align="center" style="padding:12px 32px 20px"><a href="{safe_link}" style="display:inline-block;background:#C4471D;color:#ffffff;
text-decoration:none;font-weight:bold;font-size:15px;padding:12px 22px;border-radius:8px">Confirm my email</a></td></tr>
<tr><td style="padding:0 32px 28px;font-size:13px;line-height:1.5;color:#5B606B">The link works once and expires in {ttl_hours} hours.
If this wasn't you, ignore this email.<br><br>Demo only, no legal effect.</td></tr>
</table></td></tr></table></body></html>""",
        subtype="html",
    )
    return msg


def send_verification(to: str, name: str, link: str, ttl_hours: int) -> str:
    """Email the sign-up confirmation link. Returns "smtp" or "console". Raises MailError."""
    if not os.environ.get("SMTP_HOST"):
        print(f"\n  [email: console mode, set SMTP_HOST to really send] to {to}: confirm at {link}\n", flush=True)
        return "console"
    return _deliver(_build_verification(to, name, link, ttl_hours, _sender()), "verification link")
