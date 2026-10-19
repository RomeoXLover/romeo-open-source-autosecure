"""Leave a Microsoft Family group (kick others first if last admin, then self).

Reversed from leavefamilybutcantsoitkicksthememberfirstthenleave.har:

  GET  https://account.microsoft.com/family/api/roster
  DELETE https://account.microsoft.com/family/api/member?removeSet=Msa:{puid}

Leaving as the last admin returns 400 ``Family.NotAllowedToRemoveLastAdmin``.
The web client then DELETEs every other member and retries self.
Child accounts only attempt to leave themselves (they cannot kick parents).
"""

from __future__ import annotations

import logging
import re

import httpx

log = logging.getLogger(__name__)

_FAMILY_HOME = "https://account.microsoft.com/family/home"
_ROSTER_URL = "https://account.microsoft.com/family/api/roster"
_MEMBER_URL = "https://account.microsoft.com/family/api/member"
_LAST_ADMIN = "Family.NotAllowedToRemoveLastAdmin"

_TOKEN_RES = (
    re.compile(
        r'name="__RequestVerificationToken"[^>]*value="([^"]+)"',
        re.I | re.DOTALL,
    ),
    re.compile(
        r'value="([^"]+)"[^>]*name="__RequestVerificationToken"',
        re.I | re.DOTALL,
    ),
    re.compile(
        r'"[rR]equestVerificationToken"\s*:\s*"([^"]+)"',
    ),
)


def _g(obj: dict, *names):
    for name in names:
        if name in obj and obj[name] is not None:
            return obj[name]
    lower = {str(k).lower(): v for k, v in obj.items()}
    for name in names:
        val = lower.get(name.lower())
        if val is not None:
            return val
    return None


def _members(data: dict | None) -> list[dict]:
    if not isinstance(data, dict):
        return []
    raw = _g(data, "members", "Members") or []
    return [m for m in raw if isinstance(m, dict)]


def _is_self(member: dict) -> bool:
    flag = _g(member, "isSelf", "IsSelf")
    return bool(flag)


def _remove_set(member: dict) -> str | None:
    rs = _g(member, "removeSet", "RemoveSet")
    if isinstance(rs, str) and rs.strip():
        return rs.strip()
    puid = _g(member, "puid", "Puid")
    if puid is None:
        return None
    text = str(puid).strip()
    if not text:
        return None
    return text if text.lower().startswith("msa:") else f"Msa:{text}"


def _public_member(member: dict) -> dict:
    """Keep embed-friendly fields; drop JWTs / photos."""
    role = _g(member, "role") or (
        "child" if _g(member, "isChild", "IsChild") else "parent"
    )
    display = (
        _g(member, "displayName", "DisplayName", "fullName", "FullName", "display", "name")
        or "Unknown"
    )
    email = _g(member, "primaryId", "PrimaryId", "email", "Email") or ""
    return {
        "display": display,
        "name": display,
        "email": email,
        "role": role,
        "isSelf": _is_self(member),
        "isChild": bool(_g(member, "isChild", "IsChild")),
        "isParent": bool(_g(member, "isParent", "IsParent")),
    }


def _family_headers(
    token: str,
    *,
    qos_root: str,
    mutating: bool = False,
) -> dict[str, str]:
    headers = {
        "Accept": "application/json, text/plain, */*",
        "X-Requested-With": "XMLHttpRequest",
        "X-AMC-JSONMode": "CamelCase",
        "Referer": f"{_FAMILY_HOME}?fref=home.cards.card.family.persona",
        "__RequestVerificationToken": token,
        "Correlation-Context": (
            f"v=1,ms.b.tel.market=en-US,ms.b.qos.rootOperationName={qos_root}"
        ),
    }
    if mutating:
        headers["Origin"] = "https://account.microsoft.com"
    return headers


def _token_from_html(html: str) -> str | None:
    for cre in _TOKEN_RES:
        m = cre.search(html or "")
        if m and m.group(1).strip():
            return m.group(1).strip()
    return None


def _api_error(data) -> str | None:
    if not isinstance(data, dict):
        return None
    err = data.get("error")
    if isinstance(err, dict):
        return str(err.get("code") or err.get("message") or err) or None
    if err:
        return str(err)
    return None


async def _scrape_family_token(
    session: httpx.AsyncClient,
    fallback: str | None,
) -> str | None:
    try:
        page = await session.get(
            _FAMILY_HOME,
            headers={
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
            },
            follow_redirects=True,
        )
        token = _token_from_html(page.text or "")
        if token:
            return token
        log.warning(
            "leave_family: no RequestVerificationToken on family/home (status=%s)",
            page.status_code,
        )
    except Exception as exc:
        log.warning("leave_family: family/home GET failed: %s", exc)

    if fallback:
        return fallback
    return None


async def _get_roster(
    session: httpx.AsyncClient,
    token: str,
) -> dict:
    try:
        resp = await session.get(
            _ROSTER_URL,
            headers=_family_headers(token, qos_root="Family.React.GetFamilyRoster"),
            follow_redirects=True,
        )
    except Exception:
        log.exception("leave_family: roster request failed")
        return {}
    try:
        data = resp.json()
    except Exception:
        log.warning("leave_family: roster non-JSON status=%s", resp.status_code)
        return {}
    if not isinstance(data, dict):
        return {}
    err = _api_error(data)
    if err and not _members(data):
        log.warning("leave_family: roster error %s", err)
        return {}
    return data


async def _delete_member(
    session: httpx.AsyncClient,
    token: str,
    remove_set: str,
) -> tuple[bool, str | None]:
    if not re.fullmatch(r"[A-Za-z0-9:._-]+", remove_set or ""):
        return False, "bad_remove_set"
    try:
        resp = await session.delete(
            f"{_MEMBER_URL}?removeSet={remove_set}",
            headers=_family_headers(
                token,
                qos_root="Family.React.RemoveMember",
                mutating=True,
            ),
            follow_redirects=True,
        )
    except Exception as exc:
        log.warning("leave_family: DELETE %s failed: %s", remove_set[:40], exc)
        return False, str(exc.__class__.__name__)

    data = None
    try:
        data = resp.json()
    except Exception:
        data = None
    err = _api_error(data)
    if resp.status_code == 200 and not err:
        return True, None
    if isinstance(data, dict) and data.get("result") == 0:
        return True, None
    return False, err or str(resp.status_code)


async def leave_family(
    session: httpx.AsyncClient,
    *,
    home_token: str | None = None,
) -> dict:
    """Kick other members if needed, then leave. Soft-fails; never dumps HTML."""
    empty = {
        "attempted": False,
        "left": False,
        "kicked": 0,
        "remaining": None,
        "error": None,
    }
    token = await _scrape_family_token(session, home_token)
    if not token:
        print("[!] - Family leave skipped (no RequestVerificationToken)")
        empty["error"] = "no_token"
        return empty

    roster = await _get_roster(session, token)
    members = _members(roster)
    if not members:
        return {
            "attempted": False,
            "left": False,
            "kicked": 0,
            "remaining": [],
            "error": None,
        }

    self_m = next((m for m in members if _is_self(m)), None)
    others = [m for m in members if not _is_self(m)]
    is_child = bool(_g(roster, "isUserAChild", "IsUserAChild")) or (
        bool(_g(self_m, "isChild", "IsChild")) if self_m else False
    )
    self_role = "child" if is_child else (
        _g(self_m, "role") if self_m else "parent"
    )
    print(
        f"[~] - Microsoft Family roster: {len(members)} member(s) "
        f"(self={self_role}, others={len(others)}) — leaving"
    )

    kicked = 0
    last_err: str | None = None

    # Organizer / last admin cannot leave until others are gone.
    if not is_child:
        for member in others:
            rs = _remove_set(member)
            if not rs:
                continue
            ok, err = await _delete_member(session, token, rs)
            if ok:
                kicked += 1
                role = _g(member, "role") or "member"
                print(f"[+] - Removed family member ({role})")
            else:
                last_err = err
                log.warning("leave_family: kick failed err=%s", err)
                print(f"[X] - Family kick failed err={err}")

    left = False
    self_rs = _remove_set(self_m) if self_m else None
    if self_rs:
        ok, err = await _delete_member(session, token, self_rs)
        if (not ok) and err == _LAST_ADMIN and not is_child:
            print("[!] - Last-admin leave blocked — retrying after kicking remaining")
            roster2 = await _get_roster(session, token)
            for member in _members(roster2):
                if _is_self(member):
                    continue
                rs = _remove_set(member)
                if not rs:
                    continue
                ok2, err2 = await _delete_member(session, token, rs)
                if ok2:
                    kicked += 1
                    print("[+] - Removed family member (retry)")
                else:
                    last_err = err2
            ok, err = await _delete_member(session, token, self_rs)
        if ok:
            left = True
            print("[+] - Left Microsoft Family")
        else:
            last_err = err
            log.warning("leave_family: leave-self failed err=%s", err)
            print(f"[X] - Family leave failed err={err}")
    else:
        last_err = "no_self_puid"
        print("[X] - Family leave failed (no self puid on roster)")

    remaining_raw = _members(await _get_roster(session, token))
    remaining = [_public_member(m) for m in remaining_raw]
    if remaining:
        print(f"[!] - Still in family after leave ({len(remaining)} member(s) remain)")
    return {
        "attempted": True,
        "left": left and not remaining,
        "kicked": kicked,
        "remaining": remaining,
        "error": None if (left and not remaining) else last_err,
    }
