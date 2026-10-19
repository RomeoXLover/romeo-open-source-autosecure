"""Add an outlook.com alias and promote it to primary.

HTTP flow (names/manage canary → AddAssocId → MakePrimary → separate RemoveAlias):
- Canary comes from ``/names/manage``, not the AddAssocId HTML form.
- AddAssocId uses ``PostOption=NONE`` and treats ``alias=`` in the response
  (body or Location) as success — Microsoft often 302s without a clean HTML ok page.
- Verify by re-listing aliases on ``/names/manage``.
- MakePrimary matches the live names/manage XHR (see makeprimaryandremoveoldalias.har):
  ``Content-Type: application/x-www-form-urlencoded`` with a raw JSON body,
  ``emailChecked=false``, ``removeOldPrimary=false``. Old aliases are deleted
  afterwards via the HTML ``action=RemoveAlias`` form, not in the same API call.
"""

from __future__ import annotations

from html import unescape as html_unescape
from urllib.parse import unquote
import asyncio
import json
import logging
import re

import httpx

logger = logging.getLogger(__name__)

_FORM_CANARY_PATTERNS = (
    r'<input[^>]*id="canary"[^>]*name="canary"[^>]*value="([^"]+)"',
    r'<input[^>]*name="canary"[^>]*id="canary"[^>]*value="([^"]+)"',
    r'<input[^>]*name="canary"[^>]*value="([^"]+)"',
    r'id="canary"[^>]*value="([^"]+)"',
    r'name="canary"\s+value="([^"]+)"',
)

_MAKE_PRIMARY_HPGID = "200176"
_MAKE_PRIMARY_SCID = "100141"
_MAKE_PRIMARY_UIFLVR = "1001"


def _json_unescape(raw: str) -> str:
    if not raw:
        return ""
    try:
        return json.loads(f'"{raw}"')
    except Exception:
        return (
            raw.replace("\\/", "/")
            .replace('\\"', '"')
            .replace("\\u002b", "+")
            .replace("\\u003d", "=")
        )


def _extract_json_str(html: str, key: str) -> str | None:
    m = re.search(
        rf'"{re.escape(key)}"\s*:\s*"((?:\\.|[^"\\])*)"',
        html or "",
    )
    if not m:
        return None
    val = _json_unescape(m.group(1)).strip()
    return val or None


def _extract_form_canary(html: str) -> str | None:
    for pat in _FORM_CANARY_PATTERNS:
        m = re.search(pat, html or "", re.I)
        if m:
            return html_unescape(m.group(1))
    return None


def _extract_canary(html: str) -> str | None:
    """Form canary first (AddAssocId / RemoveAlias), then apiCanary."""
    return (
        _extract_form_canary(html)
        or _extract_json_str(html, "apiCanary")
        or _extract_json_str(html, "canary")
    )


def _tokens_from_html(html: str) -> dict[str, str | None]:
    """apiCanary / tcxt / uaid from names/manage $Config (MakePrimary XHR)."""
    form = _extract_form_canary(html)
    api = _extract_json_str(html, "apiCanary") or _extract_json_str(html, "canary") or form
    return {
        "form_canary": form,
        "api_canary": api,
        "tcxt": _extract_json_str(html, "tcxt"),
        "uaid": _extract_json_str(html, "uaid"),
    }


def _cookie_uaid(session: httpx.AsyncClient) -> str | None:
    try:
        raw = session.cookies.get("uaid")
    except Exception:
        raw = None
    if raw and re.fullmatch(r"[0-9a-f]{16,32}", str(raw), re.I):
        return str(raw)
    return None


def _signin_name_from_manage(html: str) -> str | None:
    """Current primary / membername from names/manage $Config."""
    for key in ("membername", "MemberName", "sSigninName", "signInName"):
        val = _extract_json_str(html, key)
        if val and "@" in val:
            return val.strip().lower()
    return None


def _is_names_manage_html(html: str) -> bool:
    """True when HTML is the aliases page, not login / i5600 / OAuth chrome.

    Login and Help-us-protect pages also embed a canary. Treating those as
    names/manage skipped SA elevation, then AddAssocId'd an alias that was
    already there ('try again later') and never ran MakePrimary.
    """
    if not html:
        return False
    try:
        from securing.utils.security_information import _page_id

        pid = _page_id(html)
    except Exception:
        pid = None
    blob = html.lower()
    if pid in ("i5600", "i5030"):
        return False
    if "help us protect" in blob and "arruserproofs" in blob:
        return False
    markers = (
        "idaliasemail",
        "aliasremovelink",
        "showmakeprimary",
        "showunverifiedmakeprimary",
        "managenamesform",
        "note_makeprimary",
        '"hpgid":200176',
        '"hpgid": 200176',
    )
    if any(m in blob for m in markers):
        return True
    if _signin_name_from_manage(html) and (
        "names/manage" in blob or "associatedid" in blob
    ):
        return True
    return False


def _has_make_primary_control(html: str, email: str) -> bool:
    """True if this address still has a Make primary control (still secondary)."""
    if not html or not email:
        return False
    blob = html.replace("\\u002b", "+").replace("\\/", "/")
    esc = re.escape(email.strip())
    return bool(
        re.search(rf"ShowMakePrimary\(\s*['\"]{esc}['\"]", blob, re.I)
        or re.search(rf"ShowUnverifiedMakePrimary\(\s*['\"]{esc}['\"]", blob, re.I)
    )


def _emails_from_manage(html: str) -> list[str]:
    """Collect alias emails from names/manage HTML."""
    found: list[str] = []
    for m in re.finditer(
        r'id="idAliasEmail\d+".*?<span class="dirltr\s*">([^<]+@[^<]+)</span>',
        html or "",
        re.DOTALL | re.I,
    ):
        found.append(m.group(1).strip().lower())
    # Secondary aliases also appear on Remove / Make-primary controls.
    for m in re.finditer(
        r'aliasRemoveLink[^>]*\bname=["\']([^"\']+@[^"\']+)',
        html or "",
        re.I,
    ):
        found.append(html_unescape(m.group(1)).strip().lower())
    for m in re.finditer(
        r"Show(?:Unverified)?MakePrimary\(\s*['\"]([^'\"]+@[^'\"]+)['\"]",
        html or "",
        re.I,
    ):
        found.append(m.group(1).strip().lower())
    if not found and _is_names_manage_html(html):
        # Fallback: any email-looking tokens on the manage page
        for m in re.finditer(
            r"([a-zA-Z0-9._+-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]{2,})",
            html or "",
        ):
            addr = m.group(1).strip().lower()
            if addr.endswith((".png", ".jpg", ".css", ".js")):
                continue
            if addr not in found:
                found.append(addr)
    # Primary is shown as membername, NOT idAliasEmail* — missing this made
    # MakePrimary look successful ("old gone") while the original login stayed primary.
    member = _signin_name_from_manage(html)
    if member:
        found.insert(0, member)
    # Login/MFA pages mention the username — don't treat that as an alias list.
    # Do NOT use ``login.live.com in html``: real names/manage chrome includes
    # that host and used to strip every secondary (including sunny*).
    if not _is_names_manage_html(html):
        found = [e for e in found if member and e == member]
        if not found and member:
            found = [member]
    # de-dupe preserve order
    out: list[str] = []
    seen: set[str] = set()
    for e in found:
        if e not in seen:
            seen.add(e)
            out.append(e)
    return out


def _auth_redirect_fields(html: str) -> tuple[str, str] | None:
    """Extract code+state for account.live.com/auth/redirect continue forms."""
    code_m = re.search(r'<input[^>]*name="code"[^>]*value="([^"]+)"', html or "", re.I)
    state_m = re.search(r'<input[^>]*name="state"[^>]*value="([^"]+)"', html or "", re.I)
    if code_m and state_m:
        return unquote(code_m.group(1)), unquote(state_m.group(1))
    return None


async def _submit_auth_redirect(session: httpx.AsyncClient, html: str) -> str | None:
    """POST OAuth continue form → account.live.com/auth/redirect. Returns new HTML or None."""
    pair = _auth_redirect_fields(html)
    if not pair:
        return None
    code, state = pair
    print("[~] - Submitting account.live.com/auth/redirect (OAuth MFA continue)…")
    resp = await session.post(
        "https://account.live.com/auth/redirect",
        data={"code": code, "state": state},
        headers={
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Content-Type": "application/x-www-form-urlencoded",
        },
        follow_redirects=True,
    )
    return resp.text or ""


async def _get_manage(session: httpx.AsyncClient) -> tuple[str, str | None, list[str]]:
    """GET names/manage → (html, canary, emails). Handles auth/redirect bounce once."""
    resp = await session.get(
        "https://account.live.com/names/manage",
        headers={
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        },
        follow_redirects=True,
    )
    text = resp.text or ""

    redirected = await _submit_auth_redirect(session, text)
    if redirected is not None:
        text = redirected
        # Re-fetch manage after elevation
        resp = await session.get(
            "https://account.live.com/names/manage",
            headers={
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            },
            follow_redirects=True,
        )
        text = resp.text or ""
        redirected2 = await _submit_auth_redirect(session, text)
        if redirected2 is not None:
            text = redirected2
            resp = await session.get(
                "https://account.live.com/names/manage",
                headers={
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                },
                follow_redirects=True,
            )
            text = resp.text or ""

    canary = _extract_canary(text) if _is_names_manage_html(text) else None
    if canary:
        try:
            session.cookies.set("canary", canary, domain="account.live.com")
        except Exception:
            pass
    return text, canary, _emails_from_manage(text)


def _add_looks_successful(resp: httpx.Response, local: str, full: str) -> bool:
    """Dona checks ``alias=`` in body; also honor Location / manage bounce."""
    body = resp.text or ""
    loc = ""
    try:
        loc = resp.headers.get("location") or ""
    except Exception:
        loc = ""
    blob = f"{body}\n{loc}".lower()
    full_l = full.lower()
    local_l = local.lower()

    if "alias=" in blob:
        return True
    if full_l in blob or f"associatedidlive={local_l}" in blob.replace(" ", ""):
        return True
    # Soft success tokens Microsoft uses on the confirm / names page
    if any(
        t in blob
        for t in (
            "note_associatedidadded",
            "associatedidadded",
            "aliasadded",
            "you've added",
            "you have added",
        )
    ):
        return True
    return False


def _add_hard_failure(resp: httpx.Response) -> str | None:
    """Return a reason string if the response is a clear hard reject."""
    body = (resp.text or "").lower()
    loc = (resp.headers.get("location") or "").lower()
    blob = f"{body}\n{loc}"
    checks = (
        ("already associated", "already associated"),
        ("already being used", "already being used"),
        ("not available", "not available"),
        ("isn't available", "not available"),
        ("is unavailable", "not available"),
        ("try again later", "try again later"),
        ("too many", "too many"),
        ("can't add", "can't add"),
        ("cannot add", "cannot add"),
        ("unable to add", "unable to add"),
    )
    for needle, label in checks:
        if needle in blob:
            return label
    return None


async def _add_outlook_alias(
    session: httpx.AsyncClient,
    local: str,
    canary: str,
    *,
    security_email: str | None = None,
    account_email: str | None = None,
    password: str | None = None,
) -> bool:
    """POST AddAssocId. Returns True if Microsoft accepted the new alias."""
    full = f"{local}@outlook.com"
    # Match dona: PostOption=NONE, no query string, do not follow redirects
    # (success often lives in a 302 Location with alias=).
    resp = await session.post(
        "https://account.live.com/AddAssocId",
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "Origin": "https://account.live.com",
            "Referer": "https://account.live.com/names/manage",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        },
        data={
            "canary": canary,
            "PostOption": "NONE",
            "SingleDomain": "outlook.com",
            "UpSell": "",
            "AddAssocIdOptions": "LIVE",
            "AssociatedIdLive": local,
        },
        follow_redirects=False,
    )

    hard = _add_hard_failure(resp)
    if _add_looks_successful(resp, local, full):
        print(f"[+] - Added alias ({full})")
        return True

    loc = (resp.headers.get("location") or "").lower()
    # MFA / SA interrupt — follow, elevate, retry once
    if (
        resp.status_code in (301, 302, 303, 307, 308)
        and (
            "oauth" in loc
            or "login.live.com" in loc
            or "acr_values" in loc
            or "mfa" in loc
        )
        and security_email
    ):
        print("[~] - AddAssocId redirected to MFA — elevating then retrying…")
        followed = await session.get(
            resp.headers.get("location") or loc,
            follow_redirects=True,
        )
        # Often lands on fmHF continue form with code+state → auth/redirect
        # (NOT an i5600 OTC page). Submit that first.
        body = followed.text or ""
        redirected = await _submit_auth_redirect(session, body)
        if redirected is not None:
            body = redirected
        else:
            # Genuine MFA challenge — try email OTC elevation
            body = await _follow_post_auth_forms(session, body, str(followed.url))
            html2, canary2, emails2 = await _elevate_for_names_manage(
                session,
                body,
                security_email=security_email,
                account_email=account_email,
                password=password,
            )
            body = html2
            if full.lower() in emails2:
                print(f"[+] - Added alias ({full}) — confirmed after MFA")
                return True
            if canary2:
                canary = canary2

        # After auth/redirect, refresh manage + retry AddAssocId
        _, canary2, emails2 = await _get_manage(session)
        if full.lower() in emails2:
            print(f"[+] - Added alias ({full}) — confirmed after auth/redirect")
            return True
        if canary2:
            resp = await session.post(
                "https://account.live.com/AddAssocId",
                headers={
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Origin": "https://account.live.com",
                    "Referer": "https://account.live.com/names/manage",
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                },
                data={
                    "canary": canary2,
                    "PostOption": "NONE",
                    "SingleDomain": "outlook.com",
                    "UpSell": "",
                    "AddAssocIdOptions": "LIVE",
                    "AssociatedIdLive": local,
                },
                follow_redirects=False,
            )
            if _add_looks_successful(resp, local, full):
                print(f"[+] - Added alias ({full}) after MFA retry")
                return True
            # One more auth/redirect hop if still bouncing
            loc2 = resp.headers.get("location") or ""
            if resp.status_code in (301, 302, 303) and loc2:
                hop = await session.get(loc2, follow_redirects=True)
                await _submit_auth_redirect(session, hop.text or "")
                _, _, emails3 = await _get_manage(session)
                if full.lower() in emails3:
                    print(f"[+] - Added alias ({full}) — confirmed after 2nd auth/redirect")
                    return True

    # Always verify via names/manage — HTML error strings are noisy false positives
    # (old bug: "not available"/"can't add" in chrome → skip MakePrimary → delete alias).
    _, _, emails = await _get_manage(session)
    if full.lower() in emails:
        print(f"[+] - Added alias ({full}) — confirmed on names/manage")
        return True

    if hard:
        logger.error(
            "AddAssocId hard-reject %s status=%s reason=%s body=%s",
            full,
            resp.status_code,
            hard,
            (resp.text or "")[:400],
        )
        print(f"[X] - Failed to add alias ({full}) — {hard}")
        return False

    logger.error(
        "AddAssocId ambiguous fail %s status=%s loc=%s body=%s",
        full,
        resp.status_code,
        resp.headers.get("location"),
        (resp.text or "")[:500],
    )
    print(f"[X] - Failed to add alias ({full})")
    return False


async def _gct_exists(email: str) -> bool | None:
    """True/False if GetCredentialType is conclusive; None if unknown.

    IfExistsResult: 0 = exists, 1 = does not exist (MS convention).
    """
    email = (email or "").strip()
    if not email or "@" not in email:
        return None
    try:
        from securing.autobuy_hold_check import fetch_credential_type

        info = await fetch_credential_type(email)
    except Exception as exc:
        logger.warning("GCT exists-check failed for %s: %s", email, exc)
        return None
    if not info:
        return None
    flag = info.get("IfExistsResult")
    if flag in (1, "1"):
        return False
    if flag in (0, "0"):
        return True
    return None


async def _confirm_primary_switched(
    session: httpx.AsyncClient,
    new_full: str,
    old_email: str | None,
) -> bool:
    """Ground-truth check after MakePrimary.

    Live UI sends ``removeOldPrimary=false``, so the old login still exists.
    Success is: names/manage reports the new address as the sign-in name, or
    it is listed without a Make-primary control. Old-login-gone (GCT) is only
    a fallback for accounts where Microsoft still deleted the previous alias.
    """
    new_l = (new_full or "").strip().lower()
    old_l = (old_email or "").strip().lower()
    if not new_l:
        return False

    try:
        await asyncio.sleep(1.0)
        html, _, aliases = await _get_manage(session)
        aliases_l = {a.strip().lower() for a in aliases}
        member = _signin_name_from_manage(html)
        page_has_mp = bool(re.search(r"ShowMakePrimary\s*\(", html or "", re.I))
        if member == new_l:
            print(f"[+] - Primary switch confirmed (membername={new_full})")
            return True
        if new_l in aliases_l and page_has_mp and not _has_make_primary_control(html, new_full):
            # Secondary aliases always have Make primary; primary does not.
            if old_l and _has_make_primary_control(html, old_email or ""):
                print(
                    f"[+] - Primary switch confirmed on manage "
                    f"({new_full} is primary, old still listed)"
                )
                return True
            if member is None:
                print(
                    f"[+] - Primary switch confirmed on manage "
                    f"({new_full} listed without Make-primary)"
                )
                return True
        logger.info(
            "manage confirm after MakePrimary: member=%s aliases=%s make_primary_new=%s",
            member,
            list(aliases_l)[:8],
            _has_make_primary_control(html, new_full),
        )
    except Exception as exc:
        logger.warning("manage confirm after MakePrimary failed: %s", exc)

    # Fallback: older accounts may still drop the previous Outlook login.
    if old_l and old_l != new_l:
        old_exists = await _gct_exists(old_l)
        new_exists = await _gct_exists(new_l)
        print(
            f"[~] - Primary switch GCT check "
            f"(old {old_l} exists={old_exists}, new {new_l} exists={new_exists})"
        )
        if old_exists is False and new_exists is not False:
            print(
                f"[+] - Primary switch confirmed via GetCredentialType "
                f"(old login {old_email} no longer exists)"
            )
            return True

    return False


async def _make_primary(
    session: httpx.AsyncClient,
    full: str,
    apicanary: str,
    *,
    tcxt: str | None = None,
    uaid: str | None = None,
) -> bool:
    """POST /API/MakePrimary matching the live names/manage XHR.

    Browser sends ``application/x-www-form-urlencoded`` with a JSON *string*
    body (not ``application/json``), ``emailChecked=false``,
    ``removeOldPrimary=false``.
    """
    if not (apicanary or "").strip():
        print(f"[X] - Failed to change primary alias ({full}) — no canary")
        return False

    uaid = (uaid or _cookie_uaid(session) or "").strip() or None

    payload: dict = {
        "aliasName": full,
        "emailChecked": False,
        "removeOldPrimary": False,
        "uiflvr": int(_MAKE_PRIMARY_UIFLVR),
    }
    if uaid:
        payload["uaid"] = str(uaid)
    payload["scid"] = int(_MAKE_PRIMARY_SCID)
    payload["hpgid"] = int(_MAKE_PRIMARY_HPGID)

    headers = {
        "Accept": "application/json",
        "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
        "X-Requested-With": "XMLHttpRequest",
        "canary": apicanary,
        "hpgid": _MAKE_PRIMARY_HPGID,
        "scid": _MAKE_PRIMARY_SCID,
        "uiflvr": _MAKE_PRIMARY_UIFLVR,
        "x-ms-apiTransport": "xhr",
        "x-ms-apiVersion": "2",
        "Origin": "https://account.live.com",
        "Referer": "https://account.live.com/names/manage",
        "Sec-Fetch-Site": "same-origin",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Dest": "empty",
    }
    if uaid:
        headers["uaid"] = str(uaid)
    if tcxt:
        headers["tcxt"] = tcxt

    body = json.dumps(payload, separators=(",", ":"))
    resp = await session.post(
        "https://account.live.com/API/MakePrimary",
        headers=headers,
        content=body,
    )

    try:
        data = resp.json() if (resp.text or "").strip() else {}
    except json.JSONDecodeError:
        if resp.status_code in (200, 204) or not (resp.text or "").strip():
            print(f"[+] - Changed Primary Alias ({full}) — empty/non-JSON OK")
            return True
        logger.error(
            "MakePrimary non-JSON for %s status=%s body=%s",
            full,
            resp.status_code,
            (resp.text or "")[:400],
        )
        print(f"[X] - Failed to change primary alias ({full})")
        return False

    if not isinstance(data, dict):
        data = {}

    if "error" in data:
        err = data.get("error") or {}
        code = str(err.get("code", "") if isinstance(err, dict) else err)
        # Opaque 500 is a dona-fork habit; still treat as tentative success
        # and let the manage-page confirm decide.
        if code == "500":
            print(f"[+] - Changed Primary Alias ({full}) — opaque 500")
            return True
        logger.error(
            "MakePrimary error for %s status=%s: %s",
            full,
            resp.status_code,
            err,
        )
        print(f"[X] - Failed to change primary alias ({full}) — {code or err}")
        return False

    if resp.status_code not in (200, 204):
        logger.error(
            "MakePrimary HTTP %s for %s body=%s",
            resp.status_code,
            full,
            (resp.text or "")[:400],
        )
        print(f"[X] - Failed to change primary alias ({full}) — HTTP {resp.status_code}")
        return False

    print(f"[+] - Changed Primary Alias ({full})")
    return True


async def _follow_post_auth_forms(session: httpx.AsyncClient, text: str, url: str = "") -> str:
    """Submit obvious SSO / continue forms after i5600 so cookies elevate."""
    from securing.utils.security_information import (
        _extract_form_action,
        _extract_hidden_fields,
        _sso_fields,
        _object_moved_href,
        _page_id,
    )

    current = text or ""
    current_url = url or ""
    for _ in range(8):
        # OAuth MFA continue → account.live.com/auth/redirect
        redirected = await _submit_auth_redirect(session, current)
        if redirected is not None:
            current = redirected
            current_url = "https://account.live.com/auth/redirect"
            continue
        moved = _object_moved_href(current)
        if moved:
            r = await session.get(moved, follow_redirects=True)
            current, current_url = r.text or "", str(r.url)
            continue
        # Accrou / proofs skip
        skip = None
        for pat in (
            r'"skip"\s*:\s*\{\s*"url"\s*:\s*"([^"]+)"',
            r'"skipUrl"\s*:\s*"([^"]+)"',
            r'"cancel"\s*:\s*\{\s*"url"\s*:\s*"([^"]+)"',
        ):
            m = re.search(pat, current)
            if m:
                skip = m.group(1).replace("\\u0026", "&").replace("\\/", "/")
                break
        if skip and ("account.live.com" in skip or "login.live.com" in skip):
            # Prefer skip on Accrou/recover interrupts so we don't stick on t0-only pages
            if "recover" in current_url.lower() or "help us secure" in current.lower():
                r = await session.get(skip, follow_redirects=True)
                current, current_url = r.text or "", str(r.url)
                continue
        sso, _missing = _sso_fields(current)
        if sso:
            r = await session.post(
                sso["action"],
                data={
                    "pprid": sso["pprid"],
                    "NAP": sso["NAP"],
                    "ANON": sso["ANON"],
                    "t": sso["t"],
                },
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                follow_redirects=True,
            )
            current, current_url = r.text or "", str(r.url)
            continue
        fields = _extract_hidden_fields(current)
        action = _extract_form_action(current, current_url)
        if action and "pprid" in fields and ("ipt" in fields or "NAP" in fields or "t" in fields):
            r = await session.post(
                action,
                data=fields,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                follow_redirects=True,
            )
            current, current_url = r.text or "", str(r.url)
            continue
        pid = _page_id(current)
        if pid not in ("i5600", "i5030"):
            break
        break
    return current


async def _elevate_for_names_manage(
    session: httpx.AsyncClient,
    html: str,
    *,
    security_email: str | None,
    account_email: str | None,
    password: str | None,
) -> tuple[str, str | None, list[str]]:
    """Pass SA_20MIN / recover / i5600 so names/manage returns a real canary.

    Live flow for compromised accounts:
      names/manage → login.srf?wp=SA_20MIN → fmHF → account.live.com/recover
      → (skip) or i5600 Help-us-protect → OTC → manage canary

    Clean accounts hit i5600 directly on SA_20MIN with
    ``fProofConfirmationRequired: true``.
    """
    from securing.utils.security_information import (
        _complete_i5600_email_otc,
        _page_id,
        _extract_url_post_sft,
        _extract_email_otc_proof,
    )

    text = html or ""
    # Always chase continue / recover forms first
    text = await _follow_post_auth_forms(session, text, "")
    canary = _extract_canary(text) if _is_names_manage_html(text) else None
    if canary and _is_names_manage_html(text):
        return text, canary, _emails_from_manage(text)

    pid = _page_id(text)
    needs_i5600 = pid == "i5600" or (
        "help us protect" in text.lower() and "arrUserProofs" in text
    )
    # OAuth MFA interrupt (AddAssocId / manage sometimes lands here)
    needs_oauth = (
        "acr_values" in text.lower()
        or "urn:microsoft:policies:mfa" in text.lower()
        or (
            "oauth20_authorize" in text.lower()
            and _extract_email_otc_proof(text) is not None
        )
    )

    if not needs_i5600 and not needs_oauth:
        # Re-hit manage after form chasing
        return await _get_manage(session)

    if not security_email or security_email in ("Couldn't Change!", "Unknown"):
        print("[X] - names/manage blocked by SA elevation and no security email")
        return text, None, _emails_from_manage(text)

    print("[~] - names/manage requires SA elevation — completing security-email MFA…")
    # Do NOT password-first: posting login_pwd on i5600 burns sFT and
    # GetOneTimeCode then returns State 203. Send security-email OTP first.
    resp = await _complete_i5600_email_otc(
        session,
        text,
        security_email=security_email,
        account_email=account_email,
        password=password,
        wait_slices=(40.0, 50.0),
        label="Names MFA",
        try_password_first=False,
    )
    if resp is None:
        print("[X] - Failed to elevate session for names/manage")
        return text, None, _emails_from_manage(text)

    await _follow_post_auth_forms(session, resp.text or "", str(getattr(resp, "url", "")))
    return await _get_manage(session)


async def change_primary_alias(
    session: httpx.AsyncClient,
    email: str,
    apicanary: str,
    *,
    security_email: str | None = None,
    account_email: str | None = None,
    password: str | None = None,
) -> bool:
    """
    ``email`` is the local-part only (e.g. sunnyabc123).
    Returns True only when the new address is confirmed primary-capable
    (added + MakePrimary accepted, or already listed after promote).
    """
    local = (email or "").strip().split("@", 1)[0]
    if not local:
        return False
    full = f"{local}@outlook.com"

    try:
        if not apicanary:
            print(f"[X] - Failed to change primary alias ({full}) — no apicanary")
            return False

        html, canary, before = await _get_manage(session)
        if not canary or not _is_names_manage_html(html):
            html, canary, before = await _elevate_for_names_manage(
                session,
                html,
                security_email=security_email,
                account_email=(
                    account_email
                    or (before[0] if before else None)
                ),
                password=password,
            )

        if not canary:
            # Fallback: try AddAssocId page canary (legacy path) after elevation
            add_page = await session.get(
                "https://account.live.com/AddAssocId",
                headers={
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
                },
                follow_redirects=True,
            )
            add_html = add_page.text or ""
            canary = _extract_canary(add_html)
            if not canary:
                from securing.utils.security_information import _page_id as _pid

                # Do NOT re-run Names MFA here — first elevate already burned the
                # OTP/password attempt. A second 2–3 minute wait is pure waste.
                if _pid(add_html) == "i5600" or "help us protect" in add_html.lower():
                    print(
                        "[!] - AddAssocId still on SA MFA after elevate — "
                        "not retrying OTP wait"
                    )
                    logger.warning(
                        "change_primary_alias: skipping second elevate on i5600"
                    )
        if not canary:
            print(f"[X] - Failed to change primary alias ({full}) — no canary")
            logger.error(
                "change_primary_alias: no canary (manage len=%s login_hint=%s)",
                len(html or ""),
                "login.live.com" in (html or "").lower(),
            )
            return False

        already = full.lower() in {e.lower() for e in before}
        if not already:
            gct = await _gct_exists(full)
            if gct:
                print(
                    f"[~] - Alias exists (GetCredentialType) ({full}) — "
                    "promoting without AddAssocId"
                )
                already = True
        if already:
            print(f"[~] - Alias already present ({full}) — promoting")
        else:
            added = await _add_outlook_alias(
                session,
                local,
                canary,
                security_email=security_email,
                account_email=account_email,
                password=password,
            )
            if not added:
                # One retry with a fresh manage canary
                _, canary2, emails2 = await _get_manage(session)
                if full.lower() in emails2:
                    print(f"[+] - Alias present after add attempt ({full})")
                elif canary2:
                    added = await _add_outlook_alias(
                        session,
                        local,
                        canary2,
                        security_email=security_email,
                        account_email=account_email,
                        password=password,
                    )
                    if not added:
                        return False
                else:
                    return False

        # MakePrimary often flakes right after AddAssocId MFA (stale canary /
        # session). Retry promote with a fresh *names/manage* apiCanary —
        # password/reset canary is a different page and will 1086 the XHR.
        ok = False
        for promo_try in range(1, 4):
            tokens: dict[str, str | None] = {}
            try:
                html_m, manage_canary, on_manage = await _get_manage(session)
                tokens = _tokens_from_html(html_m)
                api_canary = tokens.get("api_canary") or manage_canary or apicanary
                if api_canary:
                    apicanary = api_canary
                if full.lower() not in [e.lower() for e in on_manage]:
                    if promo_try == 1:
                        print(f"[X] - Alias missing before MakePrimary ({full})")
                    break
            except Exception:
                on_manage = []

            print(f"[~] - MakePrimary attempt {promo_try}/3 ({full})")
            ok = await _make_primary(
                session,
                full,
                apicanary,
                tcxt=tokens.get("tcxt"),
                uaid=tokens.get("uaid") or _cookie_uaid(session),
            )
            if ok:
                break
            if await _confirm_primary_switched(session, full, account_email):
                return True
            await asyncio.sleep(1.5 * promo_try)

        # Final ground-truth — never trust MakePrimary JSON alone (sale2026025 case:
        # API reported fail, old Outlook deleted, sunny* became the only login).
        if await _confirm_primary_switched(session, full, account_email):
            return True

        if ok:
            _, _, after = await _get_manage(session)
            if full.lower() in {a.lower() for a in after}:
                return True
            logger.warning(
                "MakePrimary OK but %s not scraped on manage (aliases=%s) — trusting API",
                full,
                after[:8],
            )
            return True

        print(f"[X] - Failed to change primary alias ({full})")
        return False

    except Exception as e:
        logger.exception("Error changing primary alias: %s", e)
        # Last-chance: MakePrimary may have thrown after MS already switched
        try:
            if await _confirm_primary_switched(session, full, account_email):
                return True
        except Exception:
            pass
        print(f"[X] - Failed to change primary alias ({full})")
        return False
