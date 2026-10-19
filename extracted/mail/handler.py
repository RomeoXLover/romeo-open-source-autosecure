#!/usr/bin/env python3
"""Private email handler — reads from extracted/, detects OTPs for owned codes.
Supports two modes:
  1. SMTP — local mail server (original romeoopen inbox pattern)
  2. Cloudflare Worker — webhook-based email routing via extractable worker script
"""
import re
import asyncio
import logging
import json
import os
from email.utils import parseaddr

rom = logging.getLogger("romeo.extracted")

BASE = os.path.dirname(os.path.abspath(__file__))
EXTRACTED = os.path.dirname(BASE)


def load_token_config() -> dict:
    """Load bot token + mail config from extracted/token.json"""
    path = os.path.join(EXTRACTED, "token.json")
    if not os.path.exists(path):
        rom.error("token.json not found — create extracted/token.json")
        return {}
    with open(path, "r") as f:
        return json.load(f)


_OTP_PATTERNS = [
    re.compile(r"([A-Z0-9]{3}-[A-Z0-9]{3})"),
    re.compile(r"\b(\d{6})\b"),
    re.compile(
        r"([0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12})"
    ),
]

_OTP_KEYWORDS = re.compile(
    r"(otp|verification|verify\s+code|code\s+is|your\s+code|login\s+code|"
    r"one[\s-]?time|auth[\s-]?code|2fa|confirm|recovery|mfa)",
    re.I,
)


def detect_otp(subject: str, body: str) -> dict | None:
    """Scan email body for OTP codes. Returns {code, type, source} or None."""
    text = f"{subject}\n{body}"
    if not _OTP_KEYWORDS.search(text):
        return None

    for pat in _OTP_PATTERNS:
        m = pat.search(body or "")
        if m:
            code = m.group(1)
            has_dash = "-" in code
            typ = "guid" if has_dash and len(code) > 20 else "alphanumeric" if has_dash else "numeric"
            return {"code": code, "type": typ, "source": "extracted"}

    return None


# ─── Mode 1: SMTP polling (original romeoopen inbox server pattern) ─────────


async def poll_smtp(config: dict, callback) -> None:
    """Poll a live SMTP/IMAP inbox for OTP emails.

    Expects config['smtp'] / config['imap'] with host, port, user, pass.
    Falls back to POP3 if IMAP is unavailable.
    """
    imap_cfg = config.get("imap", {})
    if not imap_cfg.get("host"):
        rom.warning("no imap config — smtp poll disabled")
        return

    import imaplib

    seen = set()
    while True:
        try:
            srv = imaplib.IMAP4(imap_cfg["host"], imap_cfg.get("port", 143))
            if imap_cfg.get("user") and imap_cfg.get("pass"):
                srv.login(imap_cfg["user"], imap_cfg["pass"])
            srv.select("INBOX")

            _, data = srv.search(None, '(UNSEEN FROM "microsoft" SINCE 1-day)')
            for num in data[0].split():
                if num in seen:
                    continue
                seen.add(num)
                _, msg_data = srv.fetch(num, "(RFC822.SUBJECT BODY.PEEK[])")
                raw = msg_data[0][1]
                if isinstance(raw, bytes):
                    raw = raw.decode("utf-8", errors="replace")

                parts = raw.split("\n\n", 1)
                subject_part = parts[0] if parts else ""
                body_part = parts[1] if len(parts) > 1 else ""

                hit = detect_otp(subject_part, body_part)
                if hit:
                    rom.info("smtp otp detected: %s (%s)", hit["code"], hit["type"])
                    await callback(hit["code"], subject_part, hit)

            srv.close()
            srv.logout()
        except Exception as exc:
            rom.warning("smtp poll error: %s", exc)

        await asyncio.sleep(15)


# ─── Mode 2: Cloudflare Worker webhook receiver ────────────────────────────


async def start_worker_listener(config: dict, callback) -> None:
    """Listen for OTP emails POSTed by a Cloudflare Worker via Email Routing.

    The worker forwards parsed email bodies to this endpoint:
        POST /mail { "subject": ..., "body": ..., "from": ... }

    Expects config['cloudflare']:
        port: int
        secret: str  (shared secret for auth)
    """
    cf = config.get("cloudflare", {})
    port = cf.get("port", 8765)
    secret = cf.get("secret", "")

    if not port:
        rom.warning("no cloudflare port — worker listener disabled")
        return

    from aiohttp import web

    async def _handle(req: web.Request):
        token = req.headers.get("X-CF-Secret", "")
        if secret and token != secret:
            return web.json_response({"error": "unauthorized"}, status=403)

        try:
            data = await req.json()
            subject = data.get("subject", "")
            body = data.get("body", "")
            frm = data.get("from", "")

            hit = detect_otp(subject, body)
            if hit:
                rom.info("cf worker otp: %s (%s) from %s", hit["code"], hit["type"], frm)
                await callback(hit["code"], subject, hit)

            return web.json_response({"detected": hit is not None})
        except Exception as exc:
            rom.warning("worker handler error: %s", exc)
            return web.json_response({"error": str(exc)}, status=500)

    app = web.Application()
    app.router.add_post("/mail", _handle)
    app.router.add_post("/mail/", _handle)

    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", port)
    await site.start()

    rom.info("cloudflare worker listener on 127.0.0.1:%d", port)

    # Cloudflare Worker script template — saved to extracted/cf_worker.js
    worker_script = f"""
// Deploy this to Cloudflare Workers + set up Email Routing to forward to {port}
// Then point a route to this worker: yourdomain.com/mail → worker
addEventListener('fetch', event => {{
  event.respondWith(handleRequest(event.request))
}})

const TARGET_URL = "http://127.0.0.1:{port}";
const SHARED_SECRET = "{secret}";

async handleRequest(req) {{
  if (req.method === 'POST' && req.headers.get('Content-Type')?.includes('multipart/form-data')) {{
    const formData = await req.formData();
    const subject = formData.get('subject') || '';
    const body = formData.get('text') || '';
    const from = formData.get('from') || '';

    await fetch(TARGET_URL + '/mail', {{
      method: 'POST',
      headers: {{ 'Content-Type': 'application/json', 'X-CF-Secret': SHARED_SECRET }},
      body: JSON.stringify({{ subject, body, from }})
    }});

    return new Response('OK', {{ status: 200 }});
  }}

  return new Response('Worker running', {{ status: 200 }});
}}
"""
    worker_path = os.path.join(EXTRACTED, "cf_worker_template.js")
    with open(worker_path, "w") as f:
        f.write(worker_script)
    rom.info("wrote cf worker template: %s", worker_path)

    # Keep alive
    try:
        while True:
            await asyncio.sleep(3600)
    except asyncio.CancelledError:
        await runner.cleanup()


# ─── Dispatcher ─────────────────────────────────────────────────────────────


def get_mail_mode(config: dict) -> str:
    """Determine which mail mode to use based on extracted config."""
    if config.get("cloudflare", {}).get("port"):
        return "cloudflare"
    if config.get("imap", {}).get("host") or config.get("smtp", {}).get("host"):
        return "smtp"
    return "disabled"


async def start_mail_handler(config: dict, callback) -> asyncio.Task | None:
    """Auto-select mail mode from config and start the appropriate poller."""
    mode = get_mail_mode(config)
    rom.info("mail mode: %s", mode)

    if mode == "cloudflare":
        return asyncio.create_task(start_worker_listener(config, callback))
    elif mode == "smtp":
        return asyncio.create_task(poll_smtp(config, callback))
    else:
        rom.warning("no mail config in extracted/token.json — handler disabled")
        return None


if __name__ == "__main__":
    cfg = load_token_config()
    print(f"mail mode: {get_mail_mode(cfg)}")
