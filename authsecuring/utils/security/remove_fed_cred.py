"""Remove federated sign-in credentials (Samsung / Apple / Google / GitHub / LinkedIn).

Microsoft's manage-proofs UI does NOT use DeleteProof for these. It posts:

  POST https://account.live.com/API/Proofs/RemoveFedCred
  {"fedProvider":"samsung"|"apple"|"google"|"gitHub"|"linkedIn"}

Reversed from manageproofsv2.de.js:
  removeFed() {
    JsonAsync(null, fed.urls.remove, {fedProvider: this.fedType})
  }
  fedType values wired in the page:
    'samsung' | 'apple' | 'google' | 'gitHub' | 'linkedIn'

Presence flags on the proofs page ServerData:
  isSamsungFed / isAppleFed / isGoogleFed / isGitHubFed / isLinkedInFed

Note: Apple *iCloud Keychain* and *Samsung Pass* are passkeys, not FedCred.
Those are removed via RemovePasskey in remove_proof.py.
FedCred ``apple`` / ``samsung`` = "Sign in with Apple/Samsung".
"""

from __future__ import annotations

import logging
import re

import httpx

logger = logging.getLogger(__name__)

REMOVE_FED_URL = "https://account.live.com/API/Proofs/RemoveFedCred"
PROOFS_PAGE = (
    "https://account.live.com/proofs/manage/additional"
    "?mkt=en-US&refd=account.microsoft.com&refp=security"
)

# UI fedType → API fedProvider (case-sensitive as sent by the web client)
_FED_PROVIDERS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("samsung", ("isSamsungFed", "HasSamsungFed", "hasSamsungFed")),
    ("apple", ("isAppleFed", "HasAppleFed", "hasAppleFed")),
    ("google", ("isGoogleFed", "HasGoogleFed", "hasGoogleFed")),
    ("gitHub", ("isGitHubFed", "HasGitHubFed", "hasGitHub")),
    ("linkedIn", ("isLinkedInFed", "HasLinkedInFed", "hasLinkedIn")),
)


def _flag_true(html: str, flag: str) -> bool:
    """True if ServerData has ``"flag":1`` / true (not 0/false)."""
    patterns = (
        rf'"{re.escape(flag)}"\s*:\s*1\b',
        rf'"{re.escape(flag)}"\s*:\s*true\b',
        rf'"{re.escape(flag)}"\s*:\s*"1"',
    )
    return any(re.search(p, html or "", re.I) for p in patterns)


def detect_fed_providers(html: str) -> list[str]:
    found: list[str] = []
    for provider, flags in _FED_PROVIDERS:
        if any(_flag_true(html, f) for f in flags):
            found.append(provider)
    return found


async def _remove_one(
    session: httpx.AsyncClient,
    apicanary: str,
    provider: str,
) -> bool:
    resp = await session.post(
        url=REMOVE_FED_URL,
        headers={
            "host": "account.live.com",
            "Accept": "application/json",
            "Content-Type": "application/json; charset=UTF-8",
            "X-Requested-With": "XMLHttpRequest",
            "canary": apicanary,
            "Referer": PROOFS_PAGE,
            "Origin": "https://account.live.com",
        },
        # Official client: {"fedProvider":"<fedType>"}
        json={"fedProvider": provider},
        follow_redirects=False,
    )
    body = resp.text or ""
    err_code = None
    try:
        data = resp.json()
        err = data.get("error") if isinstance(data, dict) else None
        if isinstance(err, dict):
            err_code = err.get("code")
        elif err is not None:
            err_code = err
    except Exception:
        data = None

    if resp.status_code == 200 and not err_code:
        print(f"[+] - Removed FedCred ({provider})")
        return True

    print(
        f"[X] - RemoveFedCred failed provider={provider} "
        f"status={resp.status_code} err={err_code}"
    )
    logger.warning(
        "RemoveFedCred %s failed: status=%s err=%s body=%s",
        provider,
        resp.status_code,
        err_code,
        body[:400],
    )
    return False


async def remove_fed_cred(session: httpx.AsyncClient, apicanary: str) -> dict:
    """Detect + remove Samsung/Apple/Google/GitHub/LinkedIn federated credentials."""
    if not apicanary:
        print("[!] - Skipping RemoveFedCred (no apiCanary)")
        return {"removed": [], "failed": [], "detected": []}

    try:
        page = await session.get(
            PROOFS_PAGE,
            headers={
                "Accept-Language": "en-US,en;q=0.5",
                "Referer": "https://login.live.com/",
            },
            follow_redirects=True,
        )
        html = page.text or ""
    except Exception as exc:
        logger.warning("proofs page for FedCred scrape failed: %s", exc)
        print(f"[!] - FedCred scrape failed ({exc.__class__.__name__})")
        return {"removed": [], "failed": [], "detected": []}

    detected = detect_fed_providers(html)
    if not detected:
        print("[~] - No FedCred providers linked (samsung/apple/google/…)")
        return {"removed": [], "failed": [], "detected": []}

    print(f"[~] - FedCred providers to remove: {', '.join(detected)}")
    removed: list[str] = []
    failed: list[str] = []
    for provider in detected:
        try:
            ok = await _remove_one(session, apicanary, provider)
        except Exception as exc:
            logger.warning("RemoveFedCred %s exception: %s", provider, exc)
            ok = False
        (removed if ok else failed).append(provider)

    print(
        f"[+] - RemoveFedCred done (removed={removed or 'none'}, "
        f"failed={failed or 'none'})"
    )
    return {"removed": removed, "failed": failed, "detected": detected}
