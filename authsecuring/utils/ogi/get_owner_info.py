import logging

import httpx

rom = logging.getLogger(__name__)


async def fetch_owner(session: httpx.AsyncClient, verification_token: str):
    # Uses Profile RequestVerificationToken; falls back to AMC JWT claims.

    from authsecuring.utils.ogi.owner_from_jwt import owner_info_from_amc_jwt
    from authsecuring.utils.ogi.amc_headers import amc_api_headers

    headers = build_amc_headers(
        session,
        verification_token,
        qos_root="GLOBAL.PROFILE.PERSONALINFO.GETPERSONALINFO",
    )

    try:
        get_info = await session.get(
            "https://account.microsoft.com/profile/api/v1/personal-info",
            headers=headers,
        )
    except Exception:
        rom.exception("get_owner_info request failed")
        return jwt_to_owner(session)

    body = get_info.text or ""
    if not body.strip():
        rom.warning("get_owner_info: empty status=%s", get_info.status_code)
        return jwt_to_owner(session)

    try:
        data = get_info.json()
    except Exception:
        rom.warning(
            "get_owner_info: non-JSON status=%s snippet=%r",
            get_info.status_code,
            body[:200],
        )
        return jwt_to_owner(session)

    if not isinstance(data, dict):
        return jwt_to_owner(session)

    # API returns {"error":"getPersonalInfoFailed"} when AMC session is incomplete
    if data.get("error") and not data.get("firstName") and not data.get("signInEmail"):
        rom.warning(
            "get_owner_info: API error status=%s error=%s — using AMC JWT claims",
            get_info.status_code,
            data.get("error"),
        )
        return jwt_to_owner(session)

    return data
