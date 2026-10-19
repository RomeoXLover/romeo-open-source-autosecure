"""OTP email-code login — uses a user-provided Microsoft email OTP instead of password."""
import logging
from typing import Any
import httpx

rom = logging.getLogger(__name__)

OTP_LOGIN_URL = "https://login.live.com/OTCLogin"


async def login_otp(
    sesja: httpx.AsyncClient,
    email: str,
    data: dict,
) -> bool | str:
    """Login using a Microsoft email OTP code.

    Uses OtcLoginEligibleProofs — the user provides the OTP code from their
    Microsoft email. No password or authenticator secret needed.

    Args:
        sesja: httpx client with cookie jar
        email: Microsoft account email
        data: {"otp_code": "123456"}

    Returns True on success, error string on failure.
    (Same contract as login_authenticator.)
    """
    from authsecuring.utils.security_info import get_security_info
    from authsecuring.utils.livedata import livedata
    from authsecuring.utils.credentials import get_credentials

    otp_code = (data.get("otp_code") or "").strip()
    if not otp_code:
        return "No OTP code provided"

    rom.info("otp login starting for %s", email)

    try:
        creds = await get_credentials(email)
    except Exception as exc:
        rom.warning("credential fetch failed for %s: %s", email, exc)
        return f"Credential lookup failed: {exc.__class__.__name__}"

    proofs = (creds.get("Credentials") or {}).get("OtcLoginEligibleProofs") or []
    if not proofs:
        return "Email does not have OTP login enabled"

    proof_id = proofs[0].get("data") or proofs[0].get("id")

    try:
        live = await livedata(sesja)
    except Exception:
        live = {"urlPost": "https://login.live.com/OTCLogin", "ppft": ""}

    url_post = live.get("urlPost", OTP_LOGIN_URL)

    resp = await sesja.post(
        url=url_post,
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
            ),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Upgrade-Insecure-Requests": "1",
        },
        data={
            "iUserId": "",
            "iOptout": "0",
            "passwd": "",
            "authMethod": "2",
            "OtcLoginEligibleProof": proof_id or "",
            "otc": otp_code,
            "GeneralVerify": "false",
            "PPFT": live.get("ppft", ""),
            "login": email,
            "type": "11",
            "lrt": "optype,username",
            "lrtPublic": "1",
        },
        follow_redirects=True,
    )

    rom.debug("otp login response status=%s", resp.status_code)

    if "s_OpenWindows || function()" in resp.text:
        rom.info("otp login confirmed for %s", email)
        return True

    for err_kw in ("invalid", "incorrect", "wrong", "failed", "error", "expired"):
        if err_kw in resp.text.lower():
            return f"OTP login failed — {err_kw} response from Microsoft"

    return "OTP login did not produce a session"
