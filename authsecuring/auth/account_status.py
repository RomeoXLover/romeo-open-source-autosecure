import json
import re

from securing.auth.check_locked import check_locked

# Keep patterns specific — bare "blocked" matches template strings like
# strFedInviteBlockedMsg on every normal login page (false positive).
_LOCK_HTML_PATTERNS: list[tuple[str, str]] = [
    (r"account\s+has\s+been\s+locked", "Account is locked by Microsoft"),
    (r"your\s+account\s+has\s+been\s+suspended", "Account is suspended"),
    (r"account\s+is\s+locked", "Account is locked by Microsoft"),
    (r"isaccountsuspended|account\s+suspended", "Account is suspended"),
    (r"phone\s+verification\s+required|isphonelocked", "Account is phone-locked"),
    (r"we\s+noticed\s+some\s+unusual\s+activity", "Account flagged for unusual activity"),
    (r"violated\s+our\s+terms", "Account may be restricted (ToS/abuse)"),
    (r"account\s+is\s+blocked\s+from\s+signing\s+in|restricted\s+from\s+signing\s+in", "Account is blocked from signing in"),
    (r'"isAccountBlocked"\s*:\s*true', "Account is blocked from signing in"),
    # Avoid "we don't recognize this one" — that string is embedded in login
    # page templates even when the account exists.
    (
        r"couldn'?t\s+find\s+a\s+microsoft\s+account|"
        r"could\s+not\s+find\s+a\s+microsoft\s+account|"
        r"microsoft\s+account\s+doesn'?t\s+exist|"
        r"that\s+microsoft\s+account\s+doesn'?t\s+exist",
        "Microsoft account does not exist / not recognized",
    ),
]


def lock_reason_from_html(html: str | None) -> str | None:
    if not html:
        return None
    for pattern, reason in _LOCK_HTML_PATTERNS:
        if re.search(pattern, html, re.I):
            return reason
    return None


def _value_blob(info: dict) -> str:
    """Flatten Value (str/dict) for EntityNotFound-style 500 payloads."""
    value = info.get("Value")
    if value is None:
        return ""
    if isinstance(value, dict):
        try:
            return json.dumps(value)
        except (TypeError, ValueError):
            return str(value)
    return str(value)


def lock_reason_from_check_api(info: dict | None) -> str | None:
    if not info:
        return None

    status_code = info.get("StatusCode")
    value_raw = info.get("Value")
    blob = _value_blob(info).lower()
    blob_compact = blob.replace(" ", "")

    # Explicit "does not exist" on a successful/known payload only.
    # KnowMe often returns HTTP 500 + EntityNotFound for rate-limits / flakes
    # on accounts that still exist — that must NOT hard-fail securing.
    if "doesaccountexist\":false" in blob_compact:
        return "Microsoft account does not exist / not recognized"
    if status_code is not None and 200 <= int(status_code) < 300:
        if "entitynotfound" in blob or "customer profile not found" in blob:
            return "Microsoft account does not exist / not recognized"

    if status_code is None or status_code >= 500:
        return None

    if not value_raw:
        return None

    try:
        value_data = json.loads(value_raw) if isinstance(value_raw, str) else value_raw
        status = value_data.get("status", {}) if isinstance(value_data, dict) else {}
    except (json.JSONDecodeError, KeyError, TypeError):
        return None

    if status.get("notFound") or status.get("doesAccountExist") is False:
        return "Microsoft account does not exist / not recognized"

    if status.get("isAccountSuspended"):
        reason = status.get("reasonForAccountSuspension") or ""
        if reason:
            return f"Account is suspended by Microsoft ({reason})"
        return "Account is suspended/locked by Microsoft"

    if status.get("isPhoneLocked"):
        return "Account is phone-locked (phone verification required)"

    if status.get("isAccountBlocked"):
        return "Account is blocked from signing in"

    # Lost-proof = recovery proofs missing. Recovery-code / authenticator login
    # still work — blocking here stopped sellers from selling valid accounts.
    if status.get("isAccountInLostProofState"):
        return None

    if status.get("isUnFamiliarLocationBlockSet"):
        return "Account is blocked due to unfamiliar location"

    # isAccountCompromised is advisory — Microsoft still allows recovery /
    # password login. Blocking here prevented securing accounts that sellers
    # routinely recover with a valid recovery code.
    if status.get("isAccountCompromised"):
        return None

    # isIssuePresent / isAccountInFailedLoginState are soft flags (often from
    # recent failed OTP attempts) — do not treat as locked.
    return None


async def get_account_lock_reason(email: str, login_html: str | None = None) -> str | None:
    html_reason = lock_reason_from_html(login_html)
    if html_reason:
        return html_reason

    api_info = await check_locked(email)
    return lock_reason_from_check_api(api_info)
