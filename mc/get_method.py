"""Minecraft ownership via SSID entitlements.

Reliable signal (same approach as modern ownership checkers):
  GET /entitlements/license  (Bearer SSID)
  → find item name == game_minecraft
  → source PURCHASE / MC_PURCHASE  → owned permanently
  → source GAMEPASS                → Game Pass subscription access

An MSA can still have Game Pass billing while Java is a real PURCHASE —
always prefer game_minecraft source, and PURCHASE wins over GAMEPASS if both
appear.
"""

from __future__ import annotations

import logging
import uuid
from typing import Any

import httpx

from minecraft.retry import TransientMCError, with_retries

log = logging.getLogger(__name__)

LICENSE_URL = "https://api.minecraftservices.com/entitlements/license"
MCSTORE_URL = "https://api.minecraftservices.com/entitlements/mcstore"

# game_minecraft.source values seen in the wild
PURCHASE_SOURCES = frozenset({"PURCHASE", "MC_PURCHASE", "PURCHASED"})
GAMEPASS_SOURCES = frozenset({"GAMEPASS", "GAME_PASS", "XBOX_GAME_PASS"})

TARGET_NAMES = ("game_minecraft", "product_minecraft")


def _norm_source(raw: Any) -> str | None:
    if raw is None:
        return None
    s = str(raw).strip().upper().replace("-", "_").replace(" ", "_")
    if not s:
        return None
    if s in PURCHASE_SOURCES or s in {"BUY", "BOUGHT", "OWNED"}:
        return "PURCHASE"
    if s in GAMEPASS_SOURCES or "GAMEPASS" in s or s == "GP":
        return "GAMEPASS"
    return s


def _iter_items(payload: Any) -> list[dict]:
    if not isinstance(payload, dict):
        return []
    items = payload.get("items")
    if not isinstance(items, list):
        return []
    out: list[dict] = []
    for it in items:
        if isinstance(it, dict) and it.get("name"):
            out.append(it)
    return out


def classify_entitlement_items(items: list[dict]) -> dict[str, Any]:
    """Classify ownership from entitlement items.

    Preference order:
      1) game_minecraft + PURCHASE
      2) game_minecraft + GAMEPASS
      3) product_minecraft + PURCHASE
      4) product_minecraft + GAMEPASS
    """
    by_name: dict[str, list[str]] = {n: [] for n in TARGET_NAMES}
    raw_summary: list[str] = []

    for it in items:
        name = str(it.get("name") or "").strip()
        src = _norm_source(it.get("source"))
        if name:
            label = f"{name} [{src or '?'}]"
            raw_summary.append(label)
        key = name.lower()
        if key in by_name and src in ("PURCHASE", "GAMEPASS"):
            by_name[key].append(src)

    def pick(name: str) -> str | None:
        sources = by_name.get(name) or []
        if "PURCHASE" in sources:
            return "PURCHASE"
        if "GAMEPASS" in sources:
            return "GAMEPASS"
        return None

    game_src = pick("game_minecraft")
    product_src = pick("product_minecraft")
    chosen = game_src or product_src

    method: str | None = None
    if chosen == "PURCHASE":
        method = "Purchased"
    elif chosen == "GAMEPASS":
        method = "Gamepass"

    return {
        "method": method,
        "game_minecraft_source": game_src,
        "product_minecraft_source": product_src,
        "owns_minecraft": chosen is not None,
        "items_summary": raw_summary,
        "item_count": len(items),
    }


async def _get_json(
    session: httpx.AsyncClient,
    url: str,
    *,
    headers: dict,
    label: str,
) -> dict | None:
    resp = await session.get(url, headers=headers)
    if resp.status_code in (408, 425, 429, 500, 502, 503, 504):
        raise TransientMCError(f"{label} status {resp.status_code}", status=resp.status_code)
    if resp.status_code == 401:
        # Token expired / invalid — retryable auth race
        raise TransientMCError(f"{label} unauthorized", status=401)
    if resp.status_code == 403:
        # Often no entitlement / forbidden — treat as empty, not crash
        log.info("%s forbidden (403) — treating as no items", label)
        return {"items": []}
    if resp.status_code != 200:
        log.warning("%s unexpected status %s: %s", label, resp.status_code, resp.text[:200])
        return None
    try:
        data = resp.json()
    except Exception as exc:
        raise TransientMCError(f"{label} non-JSON: {exc}") from exc
    return data if isinstance(data, dict) else None


async def _fetch_entitlements_once(ssid: str) -> dict[str, Any]:
    headers = {
        "Authorization": f"Bearer {ssid}",
        "Accept": "application/json",
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"
        ),
    }
    request_id = str(uuid.uuid4())
    license_url = f"{LICENSE_URL}?requestId={request_id}"

    async with httpx.AsyncClient(timeout=30.0) as session:
        # Primary: /entitlements/license — includes source (PURCHASE vs GAMEPASS)
        license_json = await _get_json(
            session, license_url, headers=headers, label="entitlements/license",
        )
        license_items = _iter_items(license_json) if license_json is not None else []
        classified = classify_entitlement_items(license_items)
        if classified["method"]:
            classified["endpoint"] = "license"
            classified["request_id"] = request_id
            log.info(
                "entitlements/license → %s (game_minecraft=%s) items=%s",
                classified["method"],
                classified.get("game_minecraft_source"),
                classified.get("items_summary"),
            )
            return classified

        # /entitlements/mcstore lists names only — Game Pass accounts ALSO get
        # game_minecraft here, so it cannot distinguish PURCHASE vs GAMEPASS.
        # Only use it to confirm "has some MC access" when license had no source.
        mcstore_json = await _get_json(
            session, MCSTORE_URL, headers=headers, label="entitlements/mcstore",
        )
        mcstore_items = _iter_items(mcstore_json) if mcstore_json is not None else []
        names = {str(i.get("name") or "").lower() for i in mcstore_items}
        has_game = "game_minecraft" in names or "product_minecraft" in names

        if license_items:
            # License returned items but no usable source on game/product_minecraft
            result = {
                **classified,
                "owns_minecraft": bool(classified.get("owns_minecraft") or has_game),
                "endpoint": "license",
                "request_id": request_id,
                "note": "license items present but no PURCHASE/GAMEPASS source on game_minecraft",
            }
            log.warning(
                "entitlements/license: items=%s but no classifiable game_minecraft source",
                classified.get("items_summary"),
            )
            return result

        result = {
            "method": None,
            "game_minecraft_source": None,
            "product_minecraft_source": None,
            "owns_minecraft": has_game,
            "items_summary": sorted(names) if names else classified.get("items_summary") or [],
            "item_count": len(mcstore_items),
            "endpoint": "mcstore" if mcstore_items else "license+mcstore",
            "note": (
                "mcstore has game_minecraft but no source — cannot classify; "
                "need entitlements/license"
                if has_game else
                "no game_minecraft ownership"
            ),
        }
        log.info("entitlements → %s", result["note"])
        return result


async def get_method_details(ssid: str) -> dict[str, Any]:
    """Full classification dict (method, sources, item summary)."""
    details = await with_retries(
        "get_method_details",
        lambda: _fetch_entitlements_once(ssid),
        attempts=3,
        base_delay=1.5,
        retry_on_none=False,
    )
    if not details:
        return {
            "method": None,
            "game_minecraft_source": None,
            "product_minecraft_source": None,
            "owns_minecraft": False,
            "items_summary": [],
            "item_count": 0,
            "endpoint": None,
            "error": "entitlements fetch failed",
        }
    return details


async def get_method(ssid: str) -> str | None:
    """Back-compat: return 'Purchased' | 'Gamepass' | None."""
    details = await get_method_details(ssid)
    return details.get("method")
