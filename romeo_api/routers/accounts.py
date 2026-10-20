from fastapi import APIRouter, HTTPException, Depends, Request, Body
from pydantic import BaseModel, Field
from typing import Optional, List
from app import get_db, verify_token, verify_api_key, rate_limit_check, issue_token, app

router = APIRouter(prefix="/api/v1")

class LoginRequest(BaseModel):
    email: str
    password: str

class LicenseRequest(BaseModel):
    license_key: str

class AccountValidate(BaseModel):
    email: str
    password: str

class BulkValidate(BaseModel):
    accounts: List[AccountValidate]

class LinkCreate(BaseModel):
    type: str
    cosmetic: str
    price: float
    media_url: Optional[str] = None
    expires_in_hours: int = 1
    bot_id: Optional[int] = None
    settings: Optional[dict] = {}

@router.get("/accounts/validate")
async def validate_account_get(email: str, password: str, user: str = Depends(verify_token)):
    conn = get_db()
    acct = conn.execute("SELECT * FROM romeo_users WHERE email=? AND password=?", (email, password)).fetchone()
    conn.close()
    if acct:
        return {"success": True, "valid": True, "message": "Account is valid"}
    return {"success": True, "valid": False, "message": "Account is invalid"}

@router.post("/accounts/validate")
async def validate_account(body: AccountValidate, user: str = Depends(verify_token)):
    conn = get_db()
    acct = conn.execute("SELECT * FROM romeo_users WHERE email=? AND password=?", (body.email, body.password)).fetchone()
    conn.close()
    return {"success": True, "valid": bool(acct), "message": "Account is valid" if acct else "Account is invalid"}

@router.post("/accounts/validate/bulk")
async def validate_bulk(body: BulkValidate, user: str = Depends(verify_token)):
    conn = get_db()
    results = []
    for acct in body.accounts:
        row = conn.execute("SELECT 1 FROM romeo_users WHERE email=? AND password=?", (acct.email, acct.password)).fetchone()
        results.append({"email": acct.email, "valid": bool(row)})
    conn.close()
    return {"success": True, "results": results}

@router.get("/accounts/stock")
async def get_stock(
    has_cape: Optional[bool] = None,
    cape_names: Optional[str] = None,
    exclude_capes: Optional[str] = None,
    has_rank: Optional[bool] = None,
    rank_names: Optional[str] = None,
    min_level: Optional[int] = None,
    max_level: Optional[int] = None,
    min_networth: Optional[int] = None,
    max_networth: Optional[int] = None,
    tags: Optional[str] = None,
    exclude_tags: Optional[str] = None,
    no_tfa: Optional[bool] = None,
    user: str = Depends(verify_token)
):
    conn = get_db()
    query = "SELECT * FROM romeo_users WHERE 1=1"
    params = []
    if has_rank:
        query += " AND role IS NOT NULL"
    if min_networth:
        query += " AND bot_slots >= ?"
        params.append(min_networth // 1000)
    rows = conn.execute(query, params).fetchall()
    conn.close()
    return {"success": True, "accounts": [dict(r) for r in rows[:1]]}

@router.get("/accounts/check")
async def check_accounts(user: str = Depends(verify_token), **filters):
    q = "SELECT COUNT(*) as count FROM romeo_users WHERE 1=1"
    count = get_db().execute(q).fetchone()["count"]
    return {"success": True, "exists": count > 0, "count": count}

@router.post("/links")
async def create_share_link(
    title: Optional[str] = "Premium Accounts",
    accounts: List[dict] = [],
    settings: Optional[dict] = {},
    user: str = Depends(verify_token)
):
    code = secrets.token_urlsafe(12)
    conn = get_db()
    conn.execute("INSERT INTO romeo_links (user_id, code, type, settings) VALUES (?, ?, 'share', ?)",
                 (user, code, json.dumps(settings)))
    conn.commit()
    conn.close()
    return {"success": True, "code": code, "url": f"https://romeo.wtf/share/{code}"}
