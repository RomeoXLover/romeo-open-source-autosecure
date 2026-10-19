from securing.utils.cookies.get_email_code import get_email_code
from securing.utils.cookies.get_livedata import livedata
from securing.utils.cookies.safe_cookies import dedupe_cookies, has_cookie
from urllib.parse import unquote
import asyncio
import logging
import codecs
import httpx
import json
import re


class RecoverError(Exception):
    """User-facing failure during recovery-code flow."""

    def __init__(
        self,
        reason: str,
        *,
        ms_code: object | None = None,
        credentials_changed: bool = False,
    ):
        super().__init__(reason)
        self.reason = reason
        self.ms_code = ms_code
        self.credentials_changed = credentials_changed


# ResetPassword / login copy for accounts Microsoft does not recognize.
# Keep specific — vague strings like "we don't recognize this one" / "try
# entering your microsoft account again" appear as unused i18n on valid pages.
_ACCOUNT_MISSING_PHRASES = (
    "microsoft account doesn't exist",
    "couldn't find a microsoft account",
    "could not find a microsoft account",
    "we couldn't find a microsoft account",
    "we could not find a microsoft account",
    "that microsoft account doesn't exist",
    "that microsoft account does not exist",
)

_ACCOUNT_MISSING_REASON = "Microsoft account does not exist / not recognized."


def _html_says_account_missing(body: str | None) -> bool:
    if not body:
        return False
    low = body.lower()
    return any(p in low for p in _ACCOUNT_MISSING_PHRASES)


def _server_data_says_account_missing(server_data: dict | None) -> bool:
    """ResetPassword with sErrorCode 1001/1002 = email is not an MSA.

    Do NOT treat SignInNames page / SignInName action alone as missing —
    that page also appears while tokens are still loading, on rate-limits,
    and for valid accounts that need the email re-entered.
    """
    if not isinstance(server_data, dict):
        return False
    # Already past the gate — recovery token means the account exists
    if server_data.get("sRecoveryToken"):
        return False
    err = str(server_data.get("sErrorCode") or server_data.get("iErrorCode") or "")
    # 1001/1002 = Microsoft does not recognize this sign-in name
    if err in ("1001", "1002"):
        return True
    return False


def _raise_if_account_missing(body: str | None, server_data: dict | None = None) -> None:
    if _html_says_account_missing(body) or _server_data_says_account_missing(server_data):
        raise RecoverError(_ACCOUNT_MISSING_REASON, ms_code=1300)


async def verify_password_works(
    session: httpx.AsyncClient,
    email: str,
    password: str,
    *,
    settle_delay: float = 4.0,
) -> str:
    """Check whether Microsoft accepted the new password.

    Returns: "ok" | "bad" | "unknown"

    ``bad`` = MS explicitly said the password is wrong (old password may still
    be active, or RecoverUser ignored the password field).
    ``unknown`` = rate-limit / interrupt / inconclusive — NOT the same as bad.
    """
    async def _once() -> str:
        dedupe_cookies(session)
        live = await livedata(session)
        dedupe_cookies(session)
        check = await session.post(
            url=live["urlPost"],
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "Origin": "https://login.live.com",
                "Referer": "https://login.live.com/",
            },
            data={
                "login": email,
                "loginfmt": email,
                "passwd": password,
                "PPFT": live["ppft"],
                "type": "11",
                "LoginOptions": "3",
                "ps": "2",
                "psRNGCDefaultType": "",
                "psRNGCEntropy": "",
                "psRNGCSLK": "",
                "canary": "",
                "ctx": "",
                "hpgrequestid": "",
                "PPSX": "Passpor",
                "NewUser": "1",
                "FoundMSAs": "",
                "fspost": "0",
                "i21": "0",
                "CookieDisclosure": "0",
                "IsFidoSupported": "0",
            },
            follow_redirects=False,
        )
        dedupe_cookies(session)
        text = check.text or ""
        lower = text.lower()

        # Rate-limit / soft blocks → unknown (do NOT treat as password failed)
        if any(
            s in lower
            for s in (
                "too many times",
                "try again later",
                "too many requests",
                "please wait",
                "unusual sign-in activity",
                "help us protect your account",
            )
        ):
            logging.warning("Password verify rate-limited/soft-block for %s", email)
            return "unknown"

        hard_bad = (
            "that password is incorrect" in lower
            or "your account or password is incorrect" in lower
            or '"serrorcode":"80041012"' in lower
            or 'serrorcode\\":\\"80041012' in lower
            or "serrorcode\\\":\\\"80041012" in lower
        )
        if hard_bad:
            logging.error(
                "Password verify BAD for %s (status=%s)",
                email,
                check.status_code,
            )
            return "bad"

        if (
            check.status_code in (302, 303)
            or has_cookie(session, "__Host-MSAAUTH")
            or "account.live.com" in (check.headers.get("location") or "")
        ):
            logging.info("Password verify OK for %s (status=%s)", email, check.status_code)
            return "ok"

        if "sErrTxt" in text and "incorrect" in lower:
            return "bad"

        logging.warning(
            "Password verify UNKNOWN for %s (status=%s)",
            email,
            check.status_code,
        )
        return "unknown"

    try:
        # RecoverUser password propagation is often delayed under load.
        if settle_delay > 0:
            await asyncio.sleep(settle_delay)
        result = await _once()
        # One delayed retry on hard-bad — MS sometimes returns incorrect for
        # a few seconds after RecoverUser even when the new password lands.
        if result == "bad":
            logging.warning(
                "Password verify bad for %s — retrying once after settle",
                email,
            )
            await asyncio.sleep(max(6.0, settle_delay))
            result = await _once()
        return result
    except httpx.CookieConflict as exc:
        logging.warning("Password verify CookieConflict for %s: %s", email, exc)
        dedupe_cookies(session)
        return "unknown"
    except Exception:
        logging.exception("Password verify crashed for %s", email)
        return "unknown"


MS_HEADERS = {
    "Content-type": "application/json; charset=utf-8",
    "Accept": "application/json",
    "Referer": "https://account.live.com/",
    "Origin": "https://account.live.com",
    "hpgid": "200284",
    "hpgact": "0",
}

RECOVER_SCID = 100103
RECOVER_UIFLVR = 1001

# Legacy SKI dona sent with RecoverUser. Official MS reset-password JS does NOT
# send publicKey — only scid/uaid/uiflvr + plaintext password. Sending publicKey
# with plaintext makes MS ignore the password while still rotating the RC.
RECOVER_PUBLIC_KEY = "25CE4D96CB3A09A69CD847C69FC6D40AF4A4DE12"  # unused; kept for reference

_MS_RECOVERY_CODE_ERRORS = {
    1300: "Invalid or already-used recovery code (Microsoft error 1300).",
    1301: "Recovery code rejected (Microsoft error 1301).",
    1200: "Recovery session expired — retry with the same recovery code.",
    # 6001 = ExpiredCredentials — almost always means we called RecoverUser with a
    # non-Recover token (s:/Submit wait-period). Not fixed by a "fresh" RC.
    6001: (
        "Microsoft rejected RecoverUser (error 6001 / ExpiredCredentials). "
        "Usually the recovery code only starts a waiting period (account has "
        "authenticator / protected proofs) — cannot secure immediately."
    ),
}

# Official reset-password-fabric token-type map (first char before ':').
# RecoverUser requires type Recover ("v:"). VerifyRecoveryCode often returns
# Submit ("s:") for authenticator-protected accounts → WaitFlow / SubmitRecovery
# with a multi-day recoveryDate — NOT instant password reset.
_MS_TOKEN_TYPES = {
    "v": "Recover",
    "s": "Submit",
    "a": "Authz",
    "r": "Reset",
    "e": "Email",
    "h": "HIP",
    "i": "ACSR_Init",
    "c": "ACSR_Submit",
}


def _token_type(token: str | None) -> str:
    tok = unquote(token or "").strip()
    if len(tok) < 2 or tok[1] != ":":
        return "Invalid"
    return _MS_TOKEN_TYPES.get(tok[0], f"Unknown({tok[0]})")


def _require_recover_token(token: str | None, *, proofs: list | None = None) -> str:
    """Return unquoted token if it is Recover (v:); else raise RecoverError.

    Calling RecoverUser with s:/Submit causes Microsoft error 6001 and the
    misleading 'session expired / re-submit' seller message (~70% of fails).
    """
    tok = unquote(token or "").strip()
    kind = _token_type(tok)
    if kind == "Recover":
        return tok

    proof_types = []
    for p in proofs or []:
        if isinstance(p, dict) and p.get("type"):
            proof_types.append(str(p["type"]))
    proof_note = ""
    if proof_types:
        proof_note = f" Account proofs: {', '.join(proof_types)}."

    if kind == "Submit":
        raise RecoverError(
            "Microsoft recovery code opened a waiting-period flow (token s:/Submit), "
            "not instant password reset. This usually means the account has an "
            "authenticator or protected proofs — autosecure cannot finish until "
            "Microsoft's wait ends (often ~30 days). Original recovery code should "
            "still work for the seller."
            + proof_note,
            ms_code=6001,
            credentials_changed=False,
        )
    raise RecoverError(
        f"Microsoft VerifyRecoveryCode returned token type {kind!r}, not Recover (v:). "
        "Cannot call RecoverUser."
        + proof_note,
        ms_code=6001,
        credentials_changed=False,
    )


def _extract_balanced_object(html: str, start_idx: int) -> str | None:
    if start_idx < 0 or start_idx >= len(html) or html[start_idx] != "{":
        return None
    depth = 0
    in_str = False
    esc = False
    quote = ""
    for i in range(start_idx, len(html)):
        ch = html[i]
        if in_str:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == quote:
                in_str = False
            continue
        if ch in ("'", '"'):
            in_str = True
            quote = ch
            continue
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return html[start_idx : i + 1]
    return None


def _extract_server_data(html: str) -> dict | None:
    """Parse ServerData via brace-matching (old regex stopped at first ';')."""
    for pat in (
        r"var\s+ServerData\s*=\s*\{",
        r"window\.ServerData\s*=\s*\{",
        r"ServerData\s*=\s*\{",
    ):
        m = re.search(pat, html)
        if not m:
            continue
        brace_at = html.find("{", m.start())
        raw = _extract_balanced_object(html, brace_at)
        if not raw:
            continue
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            try:
                return json.loads(raw[: raw.rfind("}") + 1])
            except json.JSONDecodeError:
                logging.warning("recover: ServerData JSON decode failed (len=%s)", len(raw))
                continue
    return None


def _parse_json(response: httpx.Response, step: str) -> dict | None:
    if not response.text.strip():
        logging.error("%s: empty response (status %s)", step, response.status_code)
        return None

    try:
        data = response.json()
    except json.JSONDecodeError:
        logging.error(
            "%s: non-JSON response (status %s): %s",
            step,
            response.status_code,
            response.text[:500],
        )
        return None

    if "error" in data and "apiCanary" not in data and "token" not in data and "recoveryCode" not in data:
        err = data.get("error") or {}
        code = err.get("code") if isinstance(err, dict) else err
        logging.error("%s: Microsoft error %s body=%s", step, code, data)
        if step == "VerifyRecoveryCode":
            try:
                code_i = int(code)
            except (TypeError, ValueError):
                code_i = None
            if code_i in _MS_RECOVERY_CODE_ERRORS:
                raise RecoverError(_MS_RECOVERY_CODE_ERRORS[code_i], ms_code=code_i)
            raise RecoverError(
                f"Recovery code rejected by Microsoft (error {code}).",
                ms_code=code,
            )
        return None

    return data


def _new_cloudscraper(proxy_url: str | None, *, what: str):
    """cloudscraper Session pinned to the residential proxy (never the VPS)."""
    import cloudscraper
    from securing.utils.proxy import apply_requests_proxy

    client = cloudscraper.create_scraper()
    client.headers.update(
        {
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/122.0.0.0 Safari/537.36"
            ),
            "Accept-Language": "en-US,en;q=0.9",
        }
    )
    apply_requests_proxy(client, proxy_url, what=what)
    return client


def _verify_recovery_code_cloudscraper_sync(
    email: str,
    recovery_code: str,
    proxy_url: str | None = None,
) -> tuple[str, str | None, dict | None]:
    """VerifyRecoveryCode only — never calls RecoverUser / SubmitRecovery.

    Returns ``(status, reason, verify_resp)`` where status is:
      - ``ok`` — Microsoft accepted the code (token returned; v: or s: both OK)
      - ``bad`` — invalid / already-used / account missing
      - ``unknown`` — network / parse / inconclusive
    Credentials are not changed by this call.
    """
    import time
    from urllib.parse import quote_plus, unquote as _unquote

    recovery_code = (recovery_code or "").strip().upper().replace(" ", "")
    if not email or not recovery_code:
        return "unknown", "Missing email or recovery code", None

    reset_url = (
        "https://account.live.com/ResetPassword.aspx"
        f"?wreply=https://login.live.com/oauth20_authorize.srf&mn={quote_plus(email)}"
    )

    try:
        from securing.utils.proxy import microsoft_proxy_url

        client = _new_cloudscraper(
            proxy_url if proxy_url is not None else microsoft_proxy_url(),
            what="VerifyRecoveryCode",
        )

        server_data = None
        for attempt in range(3):
            resp = client.get(reset_url)
            body = resp.text or ""
            if _html_says_account_missing(body):
                return "bad", _ACCOUNT_MISSING_REASON.rstrip("."), None
            server_data = _extract_server_data(body)
            if _server_data_says_account_missing(server_data):
                return "bad", _ACCOUNT_MISSING_REASON.rstrip("."), None
            if server_data:
                break
            time.sleep(1)

        if not server_data:
            return "unknown", "Recovery page ServerData missing", None

        for token_try in range(5):
            if server_data.get("sRecoveryToken") and server_data.get("apiCanary"):
                break
            time.sleep(token_try + 1)
            resp = client.get(reset_url)
            body = resp.text or ""
            if _html_says_account_missing(body):
                return "bad", _ACCOUNT_MISSING_REASON.rstrip("."), None
            new_data = _extract_server_data(body)
            if new_data:
                server_data = new_data
            if _server_data_says_account_missing(server_data):
                return "bad", _ACCOUNT_MISSING_REASON.rstrip("."), None

        if not server_data.get("sRecoveryToken") or not server_data.get("apiCanary"):
            if _server_data_says_account_missing(server_data):
                return "bad", _ACCOUNT_MISSING_REASON.rstrip("."), None
            return "unknown", "Recovery page tokens missing", None

        api_canary = server_data["apiCanary"]
        uaid = server_data.get("sUnauthSessionID", "")
        uiflvr = int(server_data.get("iUiFlavor") or RECOVER_UIFLVR)
        scid = int(server_data.get("iScenarioId") or RECOVER_SCID)
        s_token = _unquote(server_data["sRecoveryToken"])

        verify_resp = client.post(
            "https://account.live.com/API/Recovery/VerifyRecoveryCode",
            json={
                "recoveryCode": recovery_code,
                "code": recovery_code,
                "scid": scid,
                "token": s_token,
                "uaid": uaid,
                "uiflvr": uiflvr,
            },
            headers={
                "Content-Type": "application/json; charset=utf-8",
                "canary": api_canary,
            },
        ).json()
    except RecoverError as exc:
        if exc.ms_code in (1300, 1301):
            return "bad", exc.reason, None
        return "unknown", exc.reason, None
    except Exception as exc:
        logging.warning(
            "verify_recovery_code cloudscraper failed for %s: %s",
            email,
            exc.__class__.__name__,
        )
        return "unknown", f"VerifyRecoveryCode inconclusive ({exc.__class__.__name__})", None

    if not verify_resp or not verify_resp.get("token"):
        err = (verify_resp or {}).get("error") or {}
        code = err.get("code") if isinstance(err, dict) else err
        try:
            code_i = int(code)
        except (TypeError, ValueError):
            code_i = None
        if code_i in (1300, 1301):
            return (
                "bad",
                _MS_RECOVERY_CODE_ERRORS.get(
                    code_i, f"Recovery code rejected (Microsoft error {code_i})."
                ),
                verify_resp,
            )
        if code_i in _MS_RECOVERY_CODE_ERRORS:
            # Session / flow errors — code may still be valid; do not void.
            return "unknown", _MS_RECOVERY_CODE_ERRORS[code_i], verify_resp
        logging.error("VerifyRecoveryCode (check-only) failed: %s", verify_resp)
        return "unknown", "VerifyRecoveryCode returned no token", verify_resp

    # Token present = code accepted. v: (instant) and s: (wait-period) both mean
    # our stored RC is still live — stop here; never call RecoverUser/SubmitRecovery.
    kind = _token_type(verify_resp.get("token"))
    logging.info(
        "VerifyRecoveryCode check-only OK for %s token_type=%s",
        email,
        kind,
    )
    return "ok", None, verify_resp


async def check_recovery_code_valid(
    email: str,
    recovery_code: str,
) -> tuple[str, str | None]:
    """Read-only RC check for hold/pullback. Does not change credentials.

    Returns ``(ok|bad|unknown, reason)``.
    """
    from securing.utils.proxy import microsoft_proxy_url

    status, reason, _ = await asyncio.to_thread(
        _verify_recovery_code_cloudscraper_sync,
        (email or "").strip(),
        (recovery_code or "").strip(),
        microsoft_proxy_url(),
    )
    return status, reason


def _recover_cloudscraper_sync(
    email: str,
    recovery_code: str,
    new_email: str,
    new_password: str,
    proxy_url: str | None = None,
) -> str | None:
    """Dona-fork RecoverUser path via cloudscraper + the sticky residential proxy.

    httpx+proxy historically 500s RecoverUser; cloudscraper with the same
    JSON works. We still send it through IPRoyal — never the VPS — so
    password-change mail shows the residential exit, not 208.84.101.140.
    """
    import time
    from urllib.parse import quote_plus, unquote as _unquote

    from securing.utils.proxy import microsoft_proxy_url

    recovery_code = (recovery_code or "").strip().upper().replace(" ", "")
    reset_url = (
        "https://account.live.com/ResetPassword.aspx"
        f"?wreply=https://login.live.com/oauth20_authorize.srf&mn={quote_plus(email)}"
    )

    client = _new_cloudscraper(
        proxy_url if proxy_url is not None else microsoft_proxy_url(),
        what="RecoverUser",
    )

    server_data = None
    last_body = ""
    for attempt in range(3):
        resp = client.get(reset_url)
        body = resp.text or ""
        last_body = body
        _raise_if_account_missing(body)
        server_data = _extract_server_data(body)
        _raise_if_account_missing(body, server_data)
        if server_data:
            break
        time.sleep(1)

    if not server_data:
        logging.error("cloudscraper recover: no ServerData for %s", email)
        _raise_if_account_missing(last_body)
        return None

    for token_try in range(5):
        if server_data.get("sRecoveryToken") and server_data.get("apiCanary"):
            break
        time.sleep(token_try + 1)
        resp = client.get(reset_url)
        body = resp.text or ""
        last_body = body
        _raise_if_account_missing(body)
        new_data = _extract_server_data(body)
        if new_data:
            server_data = new_data
        _raise_if_account_missing(body, server_data)

    if not server_data.get("sRecoveryToken") or not server_data.get("apiCanary"):
        logging.error("cloudscraper recover: missing tokens for %s", email)
        _raise_if_account_missing(last_body, server_data)
        return None

    api_canary = server_data["apiCanary"]
    uaid = server_data.get("sUnauthSessionID", "")
    uiflvr = int(server_data.get("iUiFlavor") or RECOVER_UIFLVR)
    scid = int(server_data.get("iScenarioId") or RECOVER_SCID)
    s_token = _unquote(server_data["sRecoveryToken"])

    verify_resp = client.post(
        "https://account.live.com/API/Recovery/VerifyRecoveryCode",
        json={
            "recoveryCode": recovery_code,
            "code": recovery_code,
            "scid": scid,
            "token": s_token,
            "uaid": uaid,
            "uiflvr": uiflvr,
        },
        headers={
            "Content-Type": "application/json; charset=utf-8",
            "canary": api_canary,
        },
    ).json()

    if not verify_resp or not verify_resp.get("token"):
        err = (verify_resp or {}).get("error") or {}
        code = err.get("code") if isinstance(err, dict) else err
        try:
            code_i = int(code)
        except (TypeError, ValueError):
            code_i = None
        if code_i in _MS_RECOVERY_CODE_ERRORS:
            raise RecoverError(_MS_RECOVERY_CODE_ERRORS[code_i], ms_code=code_i)
        logging.error("cloudscraper VerifyRecoveryCode failed: %s", verify_resp)
        return None

    # Prefer canary returned by VerifyRecoveryCode (matches official fabric JS).
    if isinstance(verify_resp.get("apiCanary"), str) and verify_resp["apiCanary"]:
        api_canary = verify_resp["apiCanary"]

    # Must be v:/Recover — s:/Submit means wait-period (TOTP-protected accounts).
    proofs = server_data.get("oProofList") if isinstance(server_data, dict) else None
    recover_token = _require_recover_token(verify_resp["token"], proofs=proofs)
    print(
        f"[+] - VerifyRecoveryCode token type={_token_type(recover_token)} "
        f"(len={len(recover_token)})"
    )

    # Official reset-password fabric payload (NO publicKey). Extra publicKey +
    # missing scid/uaid/uiflvr made MS rotate RC/contact email while ignoring
    # the plaintext password — the UNVERIFIED flake.
    recover_payload = {
        "contactEmail": new_email,
        "contactEpid": "",
        "password": new_password,
        "passwordExpiryEnabled": 0,
        "scid": scid,
        "token": recover_token,
        "uaid": uaid,
        "uiflvr": uiflvr,
    }

    # Soft ban-check (non-fatal) — official UI calls this before RecoverUser.
    try:
        ban = client.post(
            "https://account.live.com/API/CheckIfBannedPassword",
            json={
                "scid": scid,
                "uaid": uaid,
                "uiflvr": uiflvr,
                "password": new_password,
            },
            headers={
                "Content-Type": "application/json; charset=utf-8",
                "Canary": api_canary,
                "canary": api_canary,
            },
        ).json()
        if isinstance(ban, dict) and ban.get("isBanned"):
            logging.error(
                "cloudscraper CheckIfBannedPassword flagged password for %s", email
            )
            print("[X] - Password flagged as banned by Microsoft")
            raise RecoverError(
                "Password rejected as banned by Microsoft — retry with a new password.",
                ms_code=None,
            )
    except RecoverError:
        raise
    except Exception:
        logging.exception("CheckIfBannedPassword soft-skip")

    for attempt in range(1, 4):
        try:
            recover_resp = client.post(
                "https://account.live.com/API/Recovery/RecoverUser",
                json=recover_payload,
                headers={
                    "Content-Type": "application/json; charset=utf-8",
                    "Canary": api_canary,
                    "canary": api_canary,
                },
            ).json()
            logging.info(
                "cloudscraper RecoverUser attempt=%s body=%s",
                attempt,
                str(recover_resp)[:400],
            )
            if recover_resp.get("recoveryCode"):
                new_rc = recover_resp["recoveryCode"]
                print(
                    f"[+] - RecoverUser OK via cloudscraper "
                    f"(password length={len(new_password)}, attempt={attempt})"
                )
                print(f"[+] - New recovery code: {new_rc}")
                logging.info(
                    "cloudscraper RecoverUser new recoveryCode=%s contactEmail=%s",
                    new_rc,
                    new_email,
                )
                return new_rc
            err = recover_resp.get("error") or {}
            code = err.get("code") if isinstance(err, dict) else err
            try:
                code_i = int(code)
            except (TypeError, ValueError):
                code_i = None
            if code_i == 6001:
                raise RecoverError(
                    _MS_RECOVERY_CODE_ERRORS[6001],
                    ms_code=6001,
                )
            if code_i in _MS_RECOVERY_CODE_ERRORS:
                raise RecoverError(_MS_RECOVERY_CODE_ERRORS[code_i], ms_code=code_i)
        except RecoverError:
            raise
        except Exception:
            logging.exception("cloudscraper RecoverUser exception attempt=%s", attempt)
        if attempt < 3:
            time.sleep(attempt * 2)

    logging.error("cloudscraper RecoverUser failed after retries for %s", email)
    return None


async def recover(
    session: httpx.AsyncClient,
    email: str,
    recovery_code: str,
    new_email: str,
    new_password: str,
):
    """Automates recovery via recovery code.

    Prefer cloudscraper (dona TLS fingerprint) on the same sticky residential
    proxy as login. Bare cloudscraper used the VPS IP and Microsoft stamped
    that on password-change mail. Falls back to the httpx session path
    (also proxied) if RecoverUser 500s.

    Raises RecoverError for invalid recovery codes / known MS rejects.
    Returns the new recovery code string on success, or None on soft failure.
    """
    from securing.utils.proxy import microsoft_proxy_url

    recovery_code = (recovery_code or "").strip().upper().replace(" ", "")
    proxy_url = microsoft_proxy_url(session)

    # --- Primary: dona cloudscraper path (residential proxy, never VPS) ---
    try:
        print("[~] RecoverUser via cloudscraper (sticky residential proxy)")
        cs_rc = await asyncio.to_thread(
            _recover_cloudscraper_sync,
            email,
            recovery_code,
            new_email,
            new_password,
            proxy_url,
        )
        if cs_rc:
            return cs_rc
        logging.warning(
            "cloudscraper recover returned None for %s — falling back to httpx path",
            email,
        )
    except RecoverError:
        raise
    except Exception:
        logging.exception(
            "cloudscraper recover crashed for %s — falling back to httpx path",
            email,
        )

    reset_url = (
        "https://account.live.com/ResetPassword.aspx"
        f"?wreply=https://login.live.com/oauth20_authorize.srf&mn={email}"
    )

    server_data: dict | None = None
    body_text = ""

    # --- ResetPassword with retries (dona: 3x ServerData + token backoff) ---
    for attempt in range(1, 4):
        data = await session.get(url=reset_url, follow_redirects=True)
        body_text = data.text or ""
        body_l = body_text.lower()
        logging.info(
            "sRecovery: attempt=%s status=%s url=%s len=%s body=%s",
            attempt,
            data.status_code,
            data.url,
            len(body_text),
            body_text[:1200],
        )

        if _html_says_account_missing(body_text) or _server_data_says_account_missing(
            server_data
        ):
            raise RecoverError(_ACCOUNT_MISSING_REASON, ms_code=1300)

        if len(body_text) < 500 and (
            "please retry after sometime" in body_l
            or "try using a different device or network" in body_l
            or "too many requests" in body_l
        ):
            logging.error(
                "recover: ResetPassword rate-limited for %s body=%r",
                email,
                body_text[:200],
            )
            if attempt < 3:
                await asyncio.sleep(attempt)
                continue
            raise httpx.RemoteProtocolError(
                f"ResetPassword rate-limited/blocked for {email}"
            )

        server_data = _extract_server_data(body_text)
        if _server_data_says_account_missing(server_data):
            raise RecoverError(_ACCOUNT_MISSING_REASON, ms_code=1300)
        if server_data and server_data.get("sRecoveryToken") and server_data.get("apiCanary"):
            break

        if attempt < 3:
            await asyncio.sleep(attempt)
            continue

    # Extra progressive retries if tokens still missing (dona: up to 5)
    for token_try in range(1, 6):
        if (
            server_data
            and server_data.get("sRecoveryToken")
            and server_data.get("apiCanary")
        ):
            break
        await asyncio.sleep(token_try)
        data = await session.get(url=reset_url, follow_redirects=True)
        body_text = data.text or ""
        if _html_says_account_missing(body_text):
            raise RecoverError(_ACCOUNT_MISSING_REASON, ms_code=1300)
        new_data = _extract_server_data(body_text)
        if new_data:
            server_data = new_data
        if _server_data_says_account_missing(server_data):
            raise RecoverError(_ACCOUNT_MISSING_REASON, ms_code=1300)
        logging.info(
            "recover: token retry %s/5 keys=%s",
            token_try,
            list(server_data.keys())[:12] if server_data else None,
        )

    if not server_data or "sRecoveryToken" not in server_data or "apiCanary" not in server_data:
        title_m = re.search(r"<title[^>]*>(.*?)</title>", body_text, re.I | re.S)
        title = re.sub(r"\s+", " ", title_m.group(1)).strip()[:80] if title_m else "?"
        logging.error(
            "recover: could not parse ServerData for %s (keys=%s title=%s len=%s)",
            email,
            list(server_data.keys())[:20] if server_data else None,
            title,
            len(body_text),
        )
        _raise_if_account_missing(body_text, server_data)
        body_l = body_text.lower()
        if len(body_text) < 800 or "<html" not in body_l:
            raise httpx.RemoteProtocolError(
                f"ResetPassword unparseable/short response for {email} (len={len(body_text)})"
            )
        raise RecoverError(
            "Recovery page could not be parsed (ServerData/sRecoveryToken missing). Retry."
        )

    page_canary = server_data["apiCanary"]
    uaid = server_data.get("sUnauthSessionID", "")

    # Dona uses plain unquote; keep unicode_escape as fallback for escaped tokens
    raw_token = server_data["sRecoveryToken"]
    try:
        decoded_token = unquote(raw_token)
        if "\\" in decoded_token:
            decoded_token = codecs.decode(decoded_token, "unicode_escape")
    except Exception:
        decoded_token = codecs.decode(unquote(raw_token), "unicode_escape")

    # --- VerifyRecoveryCode ---
    rec_token = await session.post(
        url="https://account.live.com/API/Recovery/VerifyRecoveryCode",
        headers={
            **MS_HEADERS,
            "Accept-encoding": "gzip, deflate, br, zstd",
            "Connection": "keep-alive",
            "canary": page_canary,
        },
        json={
            "recoveryCode": recovery_code,
            "code": recovery_code,
            "scid": RECOVER_SCID,
            "token": decoded_token,
            "uaid": uaid,
            "uiflvr": RECOVER_UIFLVR,
        },
    )

    rec_json = _parse_json(rec_token, "VerifyRecoveryCode")
    if not rec_json or "token" not in rec_json:
        return None

    # Use VerifyRecoveryCode token for RecoverUser (dona). Prefer original page
    # canary for RecoverUser — chained canaries from SendOtt/VerifyCode were
    # a common flake source and are no longer used.
    # HARD REQUIRE v:/Recover — s:/Submit → wait period (do not call RecoverUser).
    proofs = server_data.get("oProofList") if isinstance(server_data, dict) else None
    recover_token = _require_recover_token(rec_json.get("token"), proofs=proofs)
    print(
        f"[+] - VerifyRecoveryCode token type={_token_type(recover_token)} "
        f"(len={len(recover_token)})"
    )
    page_canary_for_recover = page_canary
    verify_canary = rec_json.get("apiCanary") if isinstance(rec_json.get("apiCanary"), str) else None

    # Official MS reset-password fabric payload (no publicKey).
    recover_payload = {
        "contactEmail": new_email,
        "contactEpid": "",
        "password": new_password,
        "passwordExpiryEnabled": 0,
        "scid": RECOVER_SCID,
        "token": recover_token,
        "uaid": uaid,
        "uiflvr": RECOVER_UIFLVR,
    }

    async def _post_recover_user(canary: str, label: str) -> dict | None:
        finish_secure = await session.post(
            url="https://account.live.com/API/Recovery/RecoverUser",
            headers={
                **MS_HEADERS,
                "canary": canary,
                "Canary": canary,
            },
            json=recover_payload,
        )
        logging.info(
            "RecoverUser %s status=%s body=%s",
            label,
            finish_secure.status_code,
            (finish_secure.text or "")[:800],
        )
        print(
            f"[~] RecoverUser {label} "
            f"status={finish_secure.status_code} "
            f"body={(finish_secure.text or '')[:300]}"
        )
        try:
            return finish_secure.json() if finish_secure.text.strip() else None
        except json.JSONDecodeError:
            return None

    def _error_code(finish_json: dict | None) -> int | None:
        if not finish_json or not finish_json.get("error"):
            return None
        err = finish_json.get("error") or {}
        code = err.get("code") if isinstance(err, dict) else err
        try:
            return int(code)
        except (TypeError, ValueError):
            return None

    def _raise_hard_errors(code_i: int | None) -> None:
        if code_i == 6001:
            raise RecoverError(
                _MS_RECOVERY_CODE_ERRORS[6001],
                ms_code=6001,
                credentials_changed=False,
            )
        if code_i in _MS_RECOVERY_CODE_ERRORS:
            raise RecoverError(
                _MS_RECOVERY_CODE_ERRORS[code_i],
                ms_code=code_i,
                credentials_changed=False,
            )

    logging.info(
        "RecoverUser (fast path) contactEmail=%s token_len=%s",
        new_email,
        len(recover_token) if isinstance(recover_token, str) else None,
    )
    print("[~] RecoverUser (fast path — no SendOtt/VerifyCode)")

    # --- Fast path: RecoverUser without proof OTP (dona) ---
    last_json: dict | None = None
    need_proof_fallback = False
    recover_canary = page_canary_for_recover

    for attempt in range(1, 3):
        try:
            finish_json = await _post_recover_user(recover_canary, f"fast-{attempt}")
            last_json = finish_json
            if finish_json and finish_json.get("recoveryCode"):
                new_rc = finish_json["recoveryCode"]
                print(
                    f"[+] - RecoverUser OK (password length={len(new_password)}, "
                    f"fast attempt={attempt})"
                )
                print(f"[+] - New recovery code: {new_rc}")
                logging.info(
                    "RecoverUser new recoveryCode=%s contactEmail=%s",
                    new_rc,
                    new_email,
                )
                return new_rc

            code_i = _error_code(finish_json)
            _raise_hard_errors(code_i)
            if code_i == 500:
                # MS often wants contact-email OTP verified before RecoverUser
                logging.warning(
                    "RecoverUser error 500 on fast path — falling back to SendOtt/VerifyCode"
                )
                need_proof_fallback = True
                break
            if finish_json and finish_json.get("error"):
                logging.error("RecoverUser error: %s", finish_json.get("error"))

            if attempt == 1 and verify_canary:
                recover_canary = verify_canary
                logging.info("RecoverUser: switching to VerifyRecoveryCode canary")
        except RecoverError:
            raise
        except Exception:
            logging.exception("RecoverUser fast-path exception on attempt %s", attempt)

        if attempt < 2:
            await asyncio.sleep(2)

    # --- Fallback: SendOtt → OTP → VerifyCode → RecoverUser (old reliable path) ---
    if need_proof_fallback or not (last_json and last_json.get("recoveryCode")):
        print("[~] RecoverUser fallback: verifying security email via OTP first")
        logging.info("RecoverUser proof-fallback starting for %s", email)

        canary = verify_canary or page_canary_for_recover
        send_code = await session.post(
            url="https://account.live.com/api/Proofs/SendOtt",
            headers={**MS_HEADERS, "canary": canary},
            json={
                "associationType": "None",
                "action": "VerifyNewProof",
                "channel": "Email",
                "cxt": "MP",
                "proofId": new_email,
                "scid": RECOVER_SCID,
                "token": recover_token,
                "uaid": uaid,
                "uiflvr": RECOVER_UIFLVR,
            },
        )
        response_json = _parse_json(send_code, "SendOtt")
        if not response_json or "apiCanary" not in response_json:
            raise RecoverError(
                "RecoverUser failed (Microsoft error 500) and SendOtt fallback also failed. "
                "Original recovery code should still work — retry.",
                ms_code=500,
                credentials_changed=False,
            )

        canary = response_json["apiCanary"]
        code = await get_email_code(new_email, timeout=150)
        if not code:
            raise RecoverError(
                "RecoverUser needs security-email OTP, but no code arrived. "
                "Original recovery code should still work — retry.",
                ms_code=500,
                credentials_changed=False,
            )

        verify_code_response = await session.post(
            url="https://account.live.com/API/Proofs/VerifyCode",
            headers={**MS_HEADERS, "canary": canary},
            json={
                "action": "VerifyOtc",
                "proofId": new_email,
                "scid": RECOVER_SCID,
                "token": recover_token,
                "uaid": uaid,
                "uiflvr": RECOVER_UIFLVR,
                "code": code,
            },
        )
        verify_json = _parse_json(verify_code_response, "VerifyCode")
        if not verify_json or "apiCanary" not in verify_json:
            raise RecoverError(
                "RecoverUser OTP verify failed. Original recovery code should still work — retry.",
                ms_code=500,
                credentials_changed=False,
            )

        canary = verify_json["apiCanary"]
        # CRITICAL: RecoverUser must keep the VerifyRecoveryCode `v:` token.
        # VerifyCode returns an `a:` token — using that causes Microsoft error 500.
        # Only the canary is refreshed from VerifyCode (matches pre-dona working path).
        a_tok = verify_json.get("token")
        logging.info(
            "RecoverUser proof-fallback keeping v: token (VerifyCode returned %s…)",
            (a_tok[:2] if isinstance(a_tok, str) else None),
        )
        print(
            f"[~] Keeping VerifyRecoveryCode v: token "
            f"(VerifyCode returned {(a_tok[:2] if isinstance(a_tok, str) else None)}:…)"
        )

        for attempt in range(1, 4):
            try:
                finish_json = await _post_recover_user(canary, f"proof-{attempt}")
                last_json = finish_json
                if finish_json and finish_json.get("recoveryCode"):
                    new_rc = finish_json["recoveryCode"]
                    print(
                        f"[+] - RecoverUser OK after proof fallback "
                        f"(password length={len(new_password)}, attempt={attempt})"
                    )
                    print(f"[+] - New recovery code: {new_rc}")
                    logging.info(
                        "RecoverUser proof-fallback recoveryCode=%s contactEmail=%s",
                        new_rc,
                        new_email,
                    )
                    return new_rc

                code_i = _error_code(finish_json)
                _raise_hard_errors(code_i)
                if finish_json and finish_json.get("error"):
                    logging.error("RecoverUser proof-fallback error: %s", finish_json.get("error"))
            except RecoverError:
                raise
            except Exception:
                logging.exception("RecoverUser proof-fallback exception on attempt %s", attempt)

            if attempt < 3:
                await asyncio.sleep(attempt * 2)

        code_i = _error_code(last_json)
        raise RecoverError(
            f"RecoverUser failed (Microsoft error {code_i or 'unknown'}). "
            "Original recovery code should still work — retry.",
            ms_code=code_i,
            credentials_changed=False,
        )

    logging.error("RecoverUser missing recoveryCode after retries: %s", last_json)
    return None


def _poll_email_otp_sync(
    mail: str,
    timeout: float = 90,
    *,
    since: float | None = None,
) -> str | None:
    """Blocking OTP poll for cloudscraper worker threads."""
    import time

    from securing.utils.cookies.get_email_code import (
        _extract_otp,
        _is_skippable_notification,
    )
    from database.database import DBConnection

    deadline = time.monotonic() + timeout
    mail_l = (mail or "").lower().strip()
    since_cutoff = None
    if since is not None:
        since_cutoff = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(since - 2))

    while time.monotonic() < deadline:
        with DBConnection() as db:
            if since_cutoff:
                rows = db.cursor.execute(
                    """
                    SELECT id, body, subject FROM `received_emails`
                    WHERE lower(to_address) = ? AND consumed = 0
                      AND received_at >= ?
                    ORDER BY id DESC
                    LIMIT 8
                    """,
                    (mail_l, since_cutoff),
                ).fetchall()
            else:
                rows = db.cursor.execute(
                    """
                    SELECT id, body, subject FROM `received_emails`
                    WHERE lower(to_address) = ? AND consumed = 0
                    ORDER BY id DESC
                    LIMIT 8
                    """,
                    (mail_l,),
                ).fetchall()

        for email_id, body, subject in rows:
            if _is_skippable_notification(subject, body or ""):
                with DBConnection() as db:
                    db.mark_used(email_id)
                continue
            code = _extract_otp(body or "")
            if code:
                with DBConnection() as db:
                    db.mark_used(email_id)
                return code
            if body and len(body) > 40:
                with DBConnection() as db:
                    db.mark_used(email_id)

        time.sleep(0.8)
    return None


def _find_security_email_proof(
    proofs: list | None, security_email: str
) -> dict | None:
    """Pick the oProofList Email proof that matches our security email."""
    email = (security_email or "").strip().lower()
    if not email or "@" not in email:
        return None
    local, _, domain = email.partition("@")
    email_proofs: list[dict] = []
    for p in proofs or []:
        if not isinstance(p, dict):
            continue
        channel = str(p.get("channel") or "").lower()
        ptype = str(p.get("type") or "").lower()
        if channel != "email" and ptype != "email":
            continue
        if not p.get("epid"):
            continue
        email_proofs.append(p)

    if not email_proofs:
        return None

    ranked: list[tuple[int, dict]] = []
    for p in email_proofs:
        name = str(p.get("name") or p.get("display") or "").lower()
        clear = str(p.get("clearDigits") or "").lower()
        score = 0
        if domain and domain in name:
            score += 10
        if clear and local.startswith(clear):
            score += 50
        if local[:2] and name.startswith(local[:2]):
            score += 20
        if email in name:
            score += 100
        ranked.append((score, p))

    ranked.sort(key=lambda x: x[0], reverse=True)
    best_score, best = ranked[0]
    if best_score <= 0 and len(email_proofs) > 1:
        logging.warning(
            "Ambiguous oProofList email proofs (%s) for %s — using first",
            len(email_proofs),
            email,
        )
    return best


def _reset_password_otp_cloudscraper_sync(
    email: str,
    security_email: str,
    new_password: str,
    proxy_url: str | None = None,
) -> bool:
    """Set password via security-email OTP on ResetPassword.aspx (HAR path).

    Flow (from passwordchange.har / reset-password fabric):
      1. GET ResetPassword.aspx → sRecoveryToken (v:) + oProofList.epid
      2. POST /api/Proofs/SendOtt  (associationType=Proof, purpose=RecoverUser)
      3. Read OTP from security email
      4. POST /API/Proofs/VerifyCode (action=OTC) → Authz token (a:)
      5. POST /API/CheckIfBannedPassword
      6. POST /API/Recovery/ResetPassword with a: token + epid + password

    This is the reliable fallback when RecoverUser returns a new RC but the
    password field was ignored, and when authenticated ChangePassword 500s.
    """
    import time
    from urllib.parse import quote_plus, unquote as _unquote

    from securing.utils.proxy import microsoft_proxy_url

    email = (email or "").strip()
    security_email = (security_email or "").strip()
    new_password = (new_password or "").strip()
    if not email or not security_email or not new_password:
        return False

    reset_url = (
        "https://account.live.com/ResetPassword.aspx"
        f"?wreply=https://login.live.com/oauth20_authorize.srf&mn={quote_plus(email)}"
    )

    client = _new_cloudscraper(
        proxy_url if proxy_url is not None else microsoft_proxy_url(),
        what="OTP ResetPassword",
    )

    server_data = None
    last_body = ""
    for attempt in range(3):
        resp = client.get(reset_url)
        last_body = resp.text or ""
        _raise_if_account_missing(last_body)
        server_data = _extract_server_data(last_body)
        _raise_if_account_missing(last_body, server_data)
        if server_data and server_data.get("sRecoveryToken") and server_data.get("apiCanary"):
            break
        time.sleep(1)

    if not server_data or not server_data.get("sRecoveryToken") or not server_data.get("apiCanary"):
        logging.error("otp-reset: missing ServerData/tokens for %s", email)
        return False

    api_canary = server_data["apiCanary"]
    uaid = server_data.get("sUnauthSessionID", "")
    uiflvr = int(server_data.get("iUiFlavor") or RECOVER_UIFLVR)
    scid = int(server_data.get("iScenarioId") or RECOVER_SCID)
    page_token = _unquote(server_data["sRecoveryToken"])

    proof = _find_security_email_proof(server_data.get("oProofList"), security_email)
    if not proof:
        logging.error(
            "otp-reset: no matching Email proof for %s on %s (proofs=%s)",
            security_email,
            email,
            [
                {
                    "name": (p or {}).get("name"),
                    "type": (p or {}).get("type"),
                    "channel": (p or {}).get("channel"),
                }
                for p in (server_data.get("oProofList") or [])[:6]
                if isinstance(p, dict)
            ],
        )
        print("[X] - OTP ResetPassword: security email not in oProofList")
        return False

    epid = str(proof["epid"])
    requires_reentry = int(proof.get("requiresReentry") or 1)
    print(
        f"[~] - OTP ResetPassword via security email "
        f"({proof.get('name') or security_email})"
    )

    def _api_headers(canary: str) -> dict:
        return {
            "Content-Type": "application/json; charset=utf-8",
            "Accept": "application/json",
            "Origin": "https://account.live.com",
            "Referer": reset_url,
            "canary": canary,
            "Canary": canary,
            "hpgid": "200284",
            "hpgact": "0",
        }

    send_payload = {
        "associationType": "Proof",
        "confirmProof": security_email,
        "epid": epid,
        "proofRequiredReentry": requires_reentry,
        "purpose": "RecoverUser",
        "scid": scid,
        "token": page_token,
        "uaid": uaid,
        "uiflvr": uiflvr,
    }

    ott_before = time.time()
    send_resp = client.post(
        "https://account.live.com/api/Proofs/SendOtt",
        json=send_payload,
        headers=_api_headers(api_canary),
    )
    try:
        send_json = send_resp.json()
    except Exception:
        logging.error("otp-reset SendOtt non-JSON: %s", (send_resp.text or "")[:300])
        return False

    if not isinstance(send_json, dict) or (
        send_json.get("error") and not send_json.get("apiCanary")
    ):
        logging.error("otp-reset SendOtt failed: %s", send_json)
        print(f"[X] - OTP ResetPassword SendOtt error: {(send_json or {}).get('error')}")
        return False

    if isinstance(send_json.get("apiCanary"), str) and send_json["apiCanary"]:
        api_canary = send_json["apiCanary"]

    # Sync DB poll (worker thread — no nested asyncio loop).
    otp = _poll_email_otp_sync(security_email, timeout=90, since=ott_before)
    if not otp:
        print("[X] - OTP ResetPassword: no security-email code arrived")
        return False
    print(f"[+] - OTP ResetPassword got code ({otp})")

    verify_payload = {
        "action": "OTC",
        "confirmProof": security_email,
        "epid": epid,
        "proofRequiredReentry": requires_reentry,
        "purpose": "RecoverUser",
        "scid": scid,
        "token": page_token,
        "uaid": uaid,
        "uiflvr": uiflvr,
        "code": otp,
    }
    verify_resp = client.post(
        "https://account.live.com/API/Proofs/VerifyCode",
        json=verify_payload,
        headers=_api_headers(api_canary),
    )
    try:
        verify_json = verify_resp.json()
    except Exception:
        logging.error("otp-reset VerifyCode non-JSON: %s", (verify_resp.text or "")[:300])
        return False

    authz_token = verify_json.get("token") if isinstance(verify_json, dict) else None
    if not authz_token or _token_type(authz_token) not in ("Authz", "Recover", "Reset"):
        err = (verify_json or {}).get("error") if isinstance(verify_json, dict) else None
        logging.error("otp-reset VerifyCode bad token: %s", verify_json)
        print(f"[X] - OTP ResetPassword VerifyCode failed: {err}")
        return False

    if isinstance(verify_json.get("apiCanary"), str) and verify_json["apiCanary"]:
        api_canary = verify_json["apiCanary"]

    print(
        f"[+] - OTP VerifyCode OK token type={_token_type(authz_token)} "
        f"(len={len(authz_token)})"
    )

    try:
        ban = client.post(
            "https://account.live.com/API/CheckIfBannedPassword",
            json={
                "scid": scid,
                "uaid": uaid,
                "uiflvr": uiflvr,
                "password": new_password,
            },
            headers=_api_headers(api_canary),
        ).json()
        if isinstance(ban, dict) and ban.get("isBanned"):
            print("[X] - OTP ResetPassword: password banned by Microsoft")
            return False
        if isinstance(ban, dict) and isinstance(ban.get("apiCanary"), str) and ban["apiCanary"]:
            api_canary = ban["apiCanary"]
    except Exception:
        logging.exception("otp-reset CheckIfBannedPassword soft-skip")

    # Official fabric _S / HAR: use a: token from VerifyCode (NOT v: page token).
    reset_payload = {
        "epid": epid,
        "expiryEnabled": False,
        "scid": scid,
        "signinName": "",
        "token": authz_token,
        "uaid": uaid,
        "uiflvr": uiflvr,
        "password": new_password,
    }
    reset_resp = client.post(
        "https://account.live.com/API/Recovery/ResetPassword",
        json=reset_payload,
        headers=_api_headers(api_canary),
    )
    try:
        reset_json = reset_resp.json() if (reset_resp.text or "").strip() else {}
    except Exception:
        logging.error("otp-reset ResetPassword non-JSON: %s", (reset_resp.text or "")[:300])
        return False

    err = reset_json.get("error") if isinstance(reset_json, dict) else None
    if err:
        code = err.get("code") if isinstance(err, dict) else err
        logging.error("otp-reset ResetPassword error=%s body=%s", code, reset_json)
        print(f"[X] - OTP ResetPassword API error: {code}")
        return False

    logging.info("otp-reset ResetPassword OK keys=%s", list(reset_json)[:8] if isinstance(reset_json, dict) else None)
    print("[+] - OTP ResetPassword OK (security-email OTC)")
    return True


async def reset_password_via_security_email_otp(
    email: str,
    security_email: str,
    new_password: str,
    proxy_url: str | None = None,
) -> bool:
    """Async wrapper — cloudscraper on the sticky residential proxy."""
    from securing.utils.proxy import microsoft_proxy_url

    try:
        print("[~] ResetPassword via security-email OTP (HAR / fabric path)")
        ok = await asyncio.to_thread(
            _reset_password_otp_cloudscraper_sync,
            email,
            security_email,
            new_password,
            proxy_url if proxy_url is not None else microsoft_proxy_url(),
        )
        return bool(ok)
    except RecoverError:
        raise
    except Exception:
        logging.exception("reset_password_via_security_email_otp crashed for %s", email)
        return False
