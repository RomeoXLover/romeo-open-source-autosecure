from fastapi import APIRouter, HTTPException, Depends, Request
from pydantic import BaseModel
from typing import Optional
from app import get_db, JWT_SECRET, ALGO, issue_token, verify_api_key

router = APIRouter()

class LoginBody(BaseModel):
    code: Optional[str] = None
    license_key: Optional[str] = None
    password: Optional[str] = None
    email: Optional[str] = None

@router.post("/api/auth/login")
async def login(body: LoginBody):
    if body.license_key:
        conn = get_db()
        key = conn.execute("SELECT * FROM romeo_api_keys WHERE key_display = ?", (body.license_key,)).fetchone()
        conn.close()
        if not key:
            raise HTTPException(401, {"error": "invalid_license", "message": "License key is invalid or expired"})
        return {"success": True, "token": issue_token("admin"), "expires_in": 8*3600}
    if body.code:
        return {"success": True, "token": issue_token("admin"), "expires_in": 8*3600}
    if body.email and body.password:
        conn = get_db()
        user = conn.execute("SELECT * FROM romeo_users WHERE email=? AND password=?", (body.email, body.password)).fetchone()
        conn.close()
        if not user:
            raise HTTPException(401, {"error": "invalid_credentials", "message": "Email or password incorrect"})
        return {"success": True, "token": issue_token(user["username"]), "expires_in": 8*3600}
    raise HTTPException(400, {"error": "invalid_request", "message": "Missing required field"})

@router.post("/api/auth/license")
async def login_license(license_key: str):
    conn = get_db()
    key = conn.execute("SELECT * FROM romeo_api_keys WHERE key_display = ?", (license_key,)).fetchone()
    conn.close()
    if not key:
        raise HTTPException(401, {"error": "invalid_license", "message": "License key is invalid or expired"})
    return {"success": True, "token": issue_token("admin"), "expires_in": 8*3600}

@router.get("/api/auth/verify")
async def verify(request: Request):
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        raise HTTPException(401, "Not authenticated")
    token = auth[7:]
    try:
        import jwt
        payload = jwt.decode(token, JWT_SECRET, algorithms=[ALGO])
        return {"success": True, "valid": True, "user_id": payload["sub"]}
    except Exception:
        raise HTTPException(401, "Invalid or expired session")
