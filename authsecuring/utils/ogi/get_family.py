import logging

import httpx

from authsecuring.utils.ogi.amc_headers import amc_api_headers

rom = logging.getLogger(__name__)


async def fetch_family(sesja: httpx.AsyncClient, verification_token: str):
    try:
        family = await sesja.get(
            "https://account.microsoft.com/home/api/family/family-summary",
            headers=build_amc_headers(
                sesja,
                verification_token,
                qos_root="GLOBAL.HOME.FAMILY.GETFAMILYSUMMARY",
            ),
            follow_redirects=True,
        )
    except Exception:
        rom.exception("get_family request failed")
        return {"members": []}

    body = family.text or ""
    if not body.strip():
        return {"members": []}
    try:
        data = family.json()
    except Exception:
        rom.warning("get_family: non-JSON status=%s", family.status_code)
        return {"members": []}
    if not isinstance(data, dict):
        return {"members": []}
    if data.get("error") and not (data.get("members") or data.get("Members")):
        rom.warning("get_family: API error %s", data.get("error"))
        return {"members": []}
    members = data.get("members") or data.get("Members")
    if not isinstance(members, list):
        members = []
    data["members"] = members
    return data
