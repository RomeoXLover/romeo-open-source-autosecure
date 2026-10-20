from fastapi import APIRouter, HTTPException, Depends, Request, Body
from app import get_db, verify_token, rate_limit_check
from pydantic import BaseModel
from typing import Optional
import uuid, time, json

router = APIRouter()

class LinkCreate(BaseModel):
    type: str
    cosmetic: str
    price: float
    expires_in_hours: int = 1
    bot_id: Optional[int] = None
    settings: dict = {}

@router.get("/api/v1/beam/me")
async def beam_me(request: Request):
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        raise HTTPException(401, {"error": "missing_api_key", "message": "No API key"})
    token = auth[7:]
    import hashlib
    key_hash = hashlib.sha256(token.encode()).hexdigest()
    conn = get_db()
    key = conn.execute("SELECT * FROM romeo_api_keys WHERE key_hash = ?", (key_hash,)).fetchone()
    conn.close()
    if not key:
        raise HTTPException(401, {"error": "invalid_api_key", "message": "API key invalid"})
    conn = get_db()
    bots = conn.execute("SELECT id, bot_name, status FROM romeo_bots WHERE user_id = ?", (key['user_id'],)).fetchall()
    links_count = conn.execute("SELECT COUNT(*) as c FROM romeo_links WHERE user_id = ?", (key['user_id'],)).fetchone()["c"]
    conn.close()
    return {
        "success": True,
        "data": {
            "role": "owner",
            "owner_user_id": key['user_id'],
            "actor_user_id": key['user_id'],
            "autosecure": {"active": True, "expires_at": "2026-12-01T00:00:00.000Z", "bot_slots": 2},
            "links": {"active": True, "expires_at": "2026-12-01T00:00:00.000Z", "days_remaining": 26},
            "limits": {"links_used": links_count, "links_max": 4},
            "bots": [dict(b) for b in bots]
        }
    }

@router.get("/api/v1/beam/catalog")
async def beam_catalog():
    return {
        "success": True,
        "data": {
            "types": [
                {"value": "hypixel", "label": "Hypixel"},
                {"value": "lunar", "label": "Lunar Client"},
                {"value": "mmc", "label": "Minemen Club"},
                {"value": "badlion", "label": "Badlion"},
                {"value": "donut", "label": "DonutSMP"},
                {"value": "mccapes", "label": "MCCapes"}
            ],
            "durations_hours": [1, 2, 4, 8],
            "bot_required": False,
            "hosts": {
                "hypixel": {
                    "store": ["hypixel.gifts", "hypixel.coupons", "myhypixel.gifts"],
                    "redirect": ["hypixel.gifts", "hypixel.coupons", "myhypixel.gifts"],
                    "tebex": ["tebex.biz", "tebex.one", "tebex.uk"]
                },
                "lunar": {"tebex": ["xsolla.one", "tebex.one"]},
                "mmc": {"tebex": ["tebex.one"]}
            }
        }
    }

@router.get("/api/v1/beam/links")
async def beam_links(bot_id: Optional[int] = None, type: Optional[str] = None, limit: int = 50, offset: int = 0, request: Request = None):
    auth = request.headers.get("Authorization", "")
    token = auth.split(" ")[1] if auth.startswith("Bearer ") else ""
    import hashlib
    key_hash = hashlib.sha256(token.encode()).hexdigest()
    conn = get_db()
    key = conn.execute("SELECT * FROM romeo_api_keys WHERE key_hash = ?", (key_hash,)).fetchone()
    if not key:
        raise HTTPException(401, {"error": "invalid_api_key"})
    rows = conn.execute("SELECT * FROM romeo_links WHERE user_id = ? ORDER BY created_at DESC LIMIT ? OFFSET ?", 
                         (key['user_id'], limit, offset)).fetchall()
    conn.close()
    links = []
    for r in rows:
        row = dict(r)
        row["url"] = f"https://hypixel.gifts/claim/{row['code']}"
        row["checkout_url"] = f"https://tebex.biz/{row['code']}"
        links.append(row)
    return {"success": True, "data": links}

@router.post("/api/v1/beam/links")
async def create_beam_link(body: LinkCreate, request: Request):
    auth = request.headers.get("Authorization", "")
    token = auth.split(" ")[1] if auth.startswith("Bearer ") else ""
    import hashlib
    key_hash = hashlib.sha256(token.encode()).hexdigest()
    conn = get_db()
    key = conn.execute("SELECT * FROM romeo_api_keys WHERE key_hash = ?", (key_hash,)).fetchone()
    if not key:
        raise HTTPException(401, {"error": "invalid_api_key"})
    code = __import__("secrets").token_urlsafe(12)
    expires_at = int(time.time()) + body.expires_in_hours * 3600
    conn.execute("INSERT INTO romeo_links (user_id, bot_index, code, type, cosmetic, price, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                 (key['user_id'], body.bot_id, code, body.type, body.cosmetic, body.price, expires_at))
    conn.commit()
    conn.close()
    store_domain = body.settings.get("store_domain", "hypixel.gifts")
    return {
        "success": True,
        "data": {
            "code": code,
            "type": body.type,
            "cosmetic": body.cosmetic,
            "price": body.price,
            "url": f"https://{store_domain}/claim/{code}",
            "checkout_url": f"https://tebex.biz/{code}",
            "expires_at": expires_at * 1000,
            "bot_id": body.bot_id,
            "settings": body.settings
        }
    }

@router.get("/api/v1/beam/links/{code}")
async def get_beam_link(code: str, request: Request):
    conn = get_db()
    row = conn.execute("SELECT * FROM romeo_links WHERE code = ?", (code,)).fetchone()
    conn.close()
    if not row:
        raise HTTPException(404, {"error": "not_found", "message": "Link not found"})
    return {"success": True, "data": dict(row)}

@router.patch("/api/v1/beam/links/{code}")
async def update_beam_link(code: str, settings: dict = Body(..., embed=False), request: Request = None):
    conn = get_db()
    conn.execute("UPDATE romeo_links SET settings = ? WHERE code = ?", (json.dumps(settings), code))
    conn.commit()
    conn.close()
    return {"success": True, "message": "Link updated", "http_status": 200}

@router.delete("/api/v1/beam/links/{code}")
async def delete_beam_link(code: str, request: Request):
    auth = request.headers.get("Authorization", "")
    import hashlib
    token = auth.split(" ")[1] if auth.startswith("Bearer ") else ""
    key_hash = hashlib.sha256(token.encode()).hexdigest()
    conn = get_db()
    conn.execute("DELETE FROM romeo_links WHERE code = ? AND EXISTS (SELECT 1 FROM romeo_api_keys WHERE key_hash = ?)", (code, key_hash))
    conn.commit()
    conn.close()
    return {"success": True, "message": "Link deleted"}

@router.get("/api/v1/beam/agents.md", include_in_schema=False)
async def agents_doc():
    return """# romeo.wtf Links Beam API

Base URL: https://romeo.wtf/api/v1/beam
Auth: Bearer API key

## Endpoints

GET  /me  - Licences, slots, bots
GET  /catalog - Allowed types, hosts, durations
GET  /links - List links
POST /links - Create link
GET  /links/{code} - Get link
PATCH /links/{code} - Update link settings
DELETE /links/{code} - Delete link

## Error Codes

| error | HTTP | Meaning |
|-------|------|---------|
| missing_api_key | 401 | No Authorization header |
| invalid_api_key | 401 | Unknown/inactive key |
| permission_denied | 403 | Key cannot do this |
| not_licensed | 403 | Links licence required |
| bot_required | 403 | bot_id required |
| forbidden | 403 | Not your link/bot |
| not_found | 404 | Unknown code |
| validation_error | 400 | Bad body |
| limit_reached | 409 | Link cap |
| rate_limit_exceeded | 429 | Too many requests |
| upstream_unavailable | 503 | Engine unreachable |
"""
