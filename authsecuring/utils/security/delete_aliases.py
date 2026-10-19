"""Remove secondary aliases via the names/manage HTML form.

Live UI (managenames JS) does NOT call /API/RemoveAlias. After MakePrimary it
sets hidden fields and submits ``document.manageNamesForm``:

    action=RemoveAlias, aliasName=..., displayName=..., canary=...

Success lands on ``noteid=Note_AssociatedIdRemoved``.
"""

from __future__ import annotations

from html import unescape as html_unescape
import logging
import re
from urllib.parse import urljoin

import httpx

logger = logging.getLogger(__name__)

_MANAGE_URL = "https://account.live.com/names/manage"


def _hidden_fields(html: str) -> dict[str, str]:
    form_m = re.search(
        r'<form[^>]*(?:id|name)=["\']manageNamesForm["\'][^>]*>(.*?)</form>',
        html or "",
        re.I | re.DOTALL,
    )
    blob = form_m.group(1) if form_m else ""
    if not blob:
        return {}
    fields: dict[str, str] = {}
    for m in re.finditer(r"<input([^>]+)>", blob, re.I):
        tag = m.group(1)
        name_m = re.search(r'\bname=["\']([^"\']+)', tag, re.I)
        if not name_m:
            continue
        val_m = re.search(r'\bvalue=["\']([^"\']*)', tag, re.I)
        fields[name_m.group(1)] = html_unescape(val_m.group(1)) if val_m else ""
    return fields


def _remove_targets(html: str, emails: list[str]) -> list[tuple[str, str]]:
    """(aliasName, displayName) for aliases that have a Remove link.

    Primary has no ``aliasRemoveLink`` — skipping those avoids posting a
    RemoveAlias for the current sign-in name.
    """
    targets: list[tuple[str, str]] = []
    seen: set[str] = set()
    for m in re.finditer(
        r"<a[^>]*aliasRemoveLink[^>]*>",
        html or "",
        re.I,
    ):
        tag = m.group(0)
        name_m = re.search(r'\bname=["\']([^"\']+)', tag, re.I)
        disp_m = re.search(r'\bdata-display=["\']([^"\']*)', tag, re.I)
        if not name_m:
            continue
        alias = html_unescape(name_m.group(1)).strip()
        display = html_unescape(disp_m.group(1)).strip() if disp_m else alias
        key = alias.lower()
        if key in seen or "@" not in alias:
            continue
        seen.add(key)
        targets.append((alias, display or alias))

    if targets:
        return targets

    # Markup fallback — treat every scraped email as removable.
    out: list[tuple[str, str]] = []
    for email in emails:
        key = email.strip().lower()
        if key in seen or "@" not in email:
            continue
        seen.add(key)
        out.append((email.strip(), email.strip()))
    return out


def _remove_succeeded(resp: httpx.Response, follow_text: str = "", follow_url: str = "") -> bool:
    blob = "\n".join(
        (
            resp.text or "",
            resp.headers.get("location") or "",
            str(resp.url or ""),
            follow_text,
            follow_url,
        )
    )
    return "Note_AssociatedIdRemoved" in blob or "associatedidremoved" in blob.lower()


async def _post_remove(
    session: httpx.AsyncClient,
    html: str,
    canary: str,
    alias: str,
    display: str,
) -> httpx.Response:
    fields = _hidden_fields(html)
    fields["canary"] = canary or fields.get("canary") or ""
    fields["action"] = "RemoveAlias"
    fields["aliasName"] = alias
    fields["displayName"] = display or alias
    return await session.post(
        _MANAGE_URL,
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Origin": "https://account.live.com",
            "Referer": _MANAGE_URL,
        },
        data=fields,
        follow_redirects=False,
    )


async def delete_aliases(
    session: httpx.AsyncClient,
    *,
    keep_email: str | None = None,
    security_email: str | None = None,
    account_email: str | None = None,
    password: str | None = None,
) -> None:
    """Remove secondary aliases. Soft-skips if the manage page has no canary.

    ``keep_email`` — never remove this address (new primary / current login).
    """
    from securing.utils.security.change_primary_alias import (
        _elevate_for_names_manage,
        _emails_from_manage,
        _extract_canary,
        _get_manage,
    )

    html, canary, emails = await _get_manage(session)
    if not canary and security_email:
        try:
            print("[~] - Alias removal needs SA elevation — elevating…")
            html, canary, emails = await _elevate_for_names_manage(
                session,
                html,
                security_email=security_email,
                account_email=account_email or keep_email,
                password=password,
            )
        except Exception as exc:
            logger.warning("delete_aliases elevate failed: %s", exc)

    if not canary:
        page_id = re.search(r'PageID" content="([^"]+)"', html or "")
        logger.warning(
            "delete_aliases: no canary (page=%s len=%s) — skipping",
            page_id.group(1) if page_id else "?",
            len(html or ""),
        )
        print("[~] - Skipping alias removal (manage page missing canary)")
        return

    if not emails:
        emails = _emails_from_manage(html)

    keep = (keep_email or "").strip().lower()
    keep_local = keep.split("@", 1)[0] if keep else ""
    targets = _remove_targets(html, emails)

    to_remove: list[tuple[str, str]] = []
    for alias, display in targets:
        alias_l = alias.strip().lower()
        local = alias_l.split("@", 1)[0]
        if keep and (alias_l == keep or (keep_local and local == keep_local)):
            print(f"[~] - Keeping primary alias ({alias})")
            continue
        to_remove.append((alias, display))

    if not to_remove:
        print("[~] - No aliases to remove")
        return

    print(f"[~] - Found Aliases ({[a for a, _ in to_remove]})")
    removed = 0
    for alias, display in to_remove:
        ok = False
        for attempt in range(1, 3):
            if attempt > 1 or not canary:
                html, canary, emails_now = await _get_manage(session)
                if not canary:
                    canary = _extract_canary(html)
                if not canary:
                    break
            resp = await _post_remove(session, html, canary, alias, display)
            follow_text = ""
            follow_url = ""
            loc = resp.headers.get("location") or ""
            if resp.status_code in (301, 302, 303, 307, 308) and loc:
                hop = await session.get(
                    urljoin(_MANAGE_URL, loc),
                    follow_redirects=True,
                )
                follow_text = hop.text or ""
                follow_url = str(hop.url or "")
            if _remove_succeeded(resp, follow_text, follow_url):
                ok = True
                break
            # Confirm by re-listing even if the note id is missing
            html, canary, emails_now = await _get_manage(session)
            still = {e.strip().lower() for e in emails_now}
            if alias.strip().lower() not in still:
                ok = True
                break
            logger.warning(
                "RemoveAlias attempt %s failed for %s status=%s loc=%s body=%s",
                attempt,
                alias,
                resp.status_code,
                loc[:160],
                (resp.text or "")[:240],
            )

        if ok:
            print(f"[+] - Removed {alias}")
            removed += 1
        else:
            print(f"[X] - Failed to remove alias ({alias})")

        html, canary, _ = await _get_manage(session)

    if removed:
        print(f"[+] - Removed {removed} foreign alias(es)")
    elif to_remove:
        print("[X] - Failed to remove foreign aliases")
