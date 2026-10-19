"""Private email handler — reads from extracted/, detects OTPs for owned codes."""
import re
import asyncio
import logging
import json
import os
from email.utils import parseaddr

rom = logging.getLogger("romeo.extracted")

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def load_token_config() -> dict:
    """Load bot token + mail credentials from extracted/token.json"""
    path = os.path.join(BASE, "token.json")
    if not os.path.exists(path):
        return {}
    with open(path, "r") as f:
        return json.load(f)


_OTP_PATTERNS = [
    re.compile(r"\b([A-Z0-9]{3}-[A-Z0-9]{3})\b"),
    re.compile(r"\b([0-9]{6})\b"),
    re.compile(r"([0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12})\b"),
]

_OTP_KEYWORDS = re.compile(
    r"(otp|verification|verify code|code is|your code|login code|"
    r"one[\s-]?time|auth[\s-]?code|2fa|confirm|recovery|mfa)",
    re.I,
)


def detect_otp(subject: str, body: str) -> dict | None:
    """Scan email for OTP codes. Returns {code, type} or None."""
    text = f"{subject}\n{body}"
    if not _OTP_KEYWORDS.search(text):
        return None

    for pat in _OTP_PATTERNS:
        m = pat.search(body or "")
        if m:
            code = m.group(1)
            typ = "guid" if "-" in code and len(code) > 20 else "numeric" if code.isdigit() and len(code) == 6 else "alphanumeric"
            return {"code": code, "type": typ, "source": "extracted"}

    return None


async def poll_imap(config: dict, callback):
    """Poll IMAP inbox for OTP emails, call callback(code, subject)."""
    imap_cfg = config.get("imap", {})
    if not imap_cfg.get("host"):
        rom.warning("no imap config — skipping mail poll")
        return

    import imaplib
    last_seen = set()

    while True:
        try:
            srv = imaplib.IMAP4(imap_cfg["host"], imap_cfg.get("port", 143))
            if imap_cfg.get("user") and imap_cfg.get("pass"):
                srv.login(imap_cfg["user"], imap_cfg["pass"])
            srv.select("INBOX")

            _, data = srv.search(None, '(UNSEEN FROM "microsoft" SINCE 1-day)')
            for num in data[0].split():
                if num in last_seen:
                    continue
                last_seen.add(num)
                _, msg_data = srv.fetch(num, "(RFC822.SUBJECT BODY.PEEK[])")
                raw = msg_data[0][1]
                if isinstance(raw, bytes):
                    raw = raw.decode("utf-8", errors="replace")
                # crude split — real impl would parse properly
                parts = raw.split("\n\n", 1)
                subject_part = parts[0] if parts else ""
                body_part = parts[1] if len(parts) > 1 else ""

                hit = detect_otp(subject_part, body_part)
                if hit:
                    rom.info("otp detected: %s (%s)", hit["code"], hit["type"])
                    await callback(hit["code"], subject_part, hit["type"])

            srv.close()
            srv.logout()
        except Exception as exc:
            rom.warning("imap poll error: %s", exc)

        await asyncio.sleep(15)


if __name__ == "__main__":
    cfg = load_token_config()
    print(f"loaded token for extracted mail handler: {bool(cfg.get('bot_token'))}")
    print(f"imap configured: {bool(cfg.get('imap', {}).get('host'))}")
