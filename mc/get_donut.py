import json
from pathlib import Path

import httpx

_CONFIG = Path(__file__).resolve().parents[1] / "config" / "config.json"


def _donut_key() -> str:
    try:
        return str(json.loads(_CONFIG.read_text()).get("tokens", {}).get("donut_key") or "").strip()
    except Exception:
        return ""


def _lookup_name(username: str) -> str:
    text = str(username or "").strip()
    if not text:
        return ""
    # "StoneNight19765 (No Java)" / "Name (MC check failed)"
    if "(" in text:
        text = text.split("(", 1)[0].strip()
    low = text.lower()
    if low in ("", "no minecraft", "unknown", "n/a", "none"):
        return ""
    if "mc check failed" in low or "child locked" in low:
        return ""
    return text.split()[0] if text else ""


def parse_donut_result(stats) -> dict | None:
    """Normalize DonutSMP /v1/stats into a result dict, or None on errors."""
    if not stats or stats is False or stats == "Failed":
        return None
    if not isinstance(stats, dict):
        return None
    if stats.get("status") not in (None, 200, "200") and "result" not in stats:
        return None
    result = stats.get("result")
    if isinstance(result, dict):
        return result
    if "money" in stats or "kills" in stats:
        return stats
    return None


def donut_money(stats) -> object:
    result = parse_donut_result(stats)
    if not result:
        return 0
    return result.get("money") or 0


async def get_donut_stats(username: str):
    donut_key = _donut_key()
    if not donut_key:
        return False

    name = _lookup_name(username)
    if not name:
        return "Failed"

    async with httpx.AsyncClient(timeout=20.0) as session:
        try:
            response = await session.post(
                url=f"https://api.donutsmp.net/v1/stats/{name}",
                headers={"Authorization": donut_key},
            )
        except Exception as exc:
            print(f"[x] - Donut stats request failed for {name}: {exc}")
            return "Failed"

        try:
            stats = response.json()
        except Exception:
            print(f"[x] - Donut stats non-JSON for {name}: {response.status_code}")
            return "Failed"

        print(stats)

        result = parse_donut_result(stats)
        if response.status_code >= 500 or result is None:
            return "Failed"

        try:
            deaths = float(result.get("deaths") or 0)
            kills = float(result.get("kills") or 0)
            result["kd"] = round(kills / deaths, 2) if deaths else kills
        except (TypeError, ValueError):
            result["kd"] = 0

        return {"status": 200, "result": result}
