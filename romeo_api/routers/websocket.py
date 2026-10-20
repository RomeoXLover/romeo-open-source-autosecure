from fastapi import APIRouter, HTTPException, Depends, WebSocket
from pydantic import BaseModel
import uuid, time, hashlib, json

router = APIRouter()

class WSMessage(BaseModel):
    type: str
    event: str = ""
    method: str = ""
    id: str = ""
    data: dict = {}
    params: dict = {}

active_connections: dict[str, WebSocket] = {}

@router.websocket("/api/")
async def websocket_endpoint(ws: WebSocket):
    await ws.accept()
    api_key_obj = None
    user_id = None
    try:
        while True:
            raw = await ws.receive_text()
            msg = json.loads(raw)
            mtype = msg.get("type")
            if mtype == "auth":
                key_hash = hashlib.sha256(msg["data"]["api_key"].encode()).hexdigest()
                conn = get_db()
                row = conn.execute("SELECT * FROM romeo_api_keys WHERE key_hash = ?", (key_hash,)).fetchone()
                conn.close()
                if not row:
                    await ws.send_json({"type": "event_response", "success": False, "error": "invalid_api_key"})
                    continue
                user_id = row["user_id"]
                api_key_obj = row
                active_connections[user_id] = ws
                await ws.send_json({"type": "event_response", "event": "auth", "success": True, "user_id": user_id})
            elif mtype == "event":
                ev = msg.get("event")
                req_id = msg.get("id", str(uuid.uuid4()))
                await ws.send_json({"type": "acknowledgement", "event": ev, "id": req_id, "success": True, "uid": str(uuid.uuid4()), "code": 200, "http_status": 200})
                if ev == "getproofs":
                    email = msg["data"]["email"]
                    await ws.send_json({"type": "event_response", "event": "getproofs", "success": True, "auth_app": False, "proofs": [{"id": email.split('@')[0]+"***@"+email.split('@')[1], "display": email, "type": "email"}]})
                elif ev == "sendotp":
                    await ws.send_json({"type": "log", "event": "otp", "id": req_id, "uid": req_id, "message": "Code sent"})
                    await ws.send_json({"type": "event_response", "event": "sendotp", "success": True, "message": "Code sent"})
                elif ev == "authapp":
                    await ws.send_json({"type": "event_response", "event": "authapp", "success": True, "msaauth": "EwAIA..."})
                elif ev == "otp":
                    await ws.send_json({"type": "log", "event": "otp", "id": req_id, "uid": req_id, "message": "Securing account..."})
                    await ws.send_json({"type": "event_response", "event": "otp", "success": True, "uid": req_id, "status": "Secured", "email": msg["data"]["email"]})
                elif ev == "recoverycode":
                    await ws.send_json({"type": "log", "event": "recoverycode", "id": req_id, "uid": req_id, "message": "Verifying recovery code..."})
                    await ws.send_json({"type": "event_response", "event": "recoverycode", "success": True, "uid": req_id, "status": "Secured"})
                elif ev == "getaccounts":
                    await ws.send_json({"type": "event_response", "event": "getaccounts", "success": True, "accounts": []})
                elif ev == "mail":
                    await ws.send_json({"type": "event_response", "event": "mail", "success": True, "email": msg["data"]["email"], "messages": []})
            elif mtype == "rpc":
                method = msg.get("method")
                req_id = msg.get("id", str(uuid.uuid4()))
                if method == "api.bots.indexes":
                    conn = get_db()
                    bots = conn.execute("SELECT id as index, bot_id, bot_name, status FROM romeo_bots").fetchall()
                    conn.close()
                    await ws.send_json({"type": "rpc_response", "id": req_id, "result": {"success": True, "bots": [dict(b) for b in bots]}})
                elif method == "api.verification.session.create":
                    sid = str(uuid.uuid4())
                    conn = get_db()
                    conn.execute("INSERT INTO romeo_sessions (id, user_id, bot_index, email, username, uuid) VALUES (?, ?, ?, ?, ?, ?)",
                                 (sid, user_id, msg["params"].get("bot_id"), msg["params"].get("email"), msg["params"].get("username"), msg["params"].get("uuid")))
                    conn.commit(); conn.close()
                    await ws.send_json({"type": "rpc_response", "id": req_id, "result": {"success": True, "session_id": sid, "bot_index": msg["params"].get("bot_id"), "bot_id": str(msg["params"].get("bot_id"))}})
                elif method == "autosecure.getProofs":
                    await ws.send_json({"type": "rpc_response", "id": req_id, "result": {"success": True, "auth_app": False, "proofs": [{"id": "e***@x.com", "display": "e***@x.com", "type": "email"}]}})
                elif method == "autosecure.sendOtp":
                    await ws.send_json({"type": "rpc_response", "id": req_id, "result": {"success": True, "message": "Code sent"}})
                elif method == "autosecure.authApp":
                    await ws.send_json({"type": "rpc_response", "id": req_id, "result": {"success": True, "msaauth": "EwAIA..."}})
                elif method.startswith("secure."):
                    await ws.send_json({"type": "rpc_response", "id": req_id, "result": {"success": True, "uid": str(uuid.uuid4()), "message": "Queued"}})
                else:
                    await ws.send_json({"type": "rpc_response", "id": req_id, "error": "unknown_method", "message": f"Unknown method: {method}"})
    except Exception as e:
        await ws.send_json({"type": "error", "message": str(e)})
    finally:
        if user_id and user_id in active_connections:
            del active_connections[user_id]
        await ws.close()

from pydantic import BaseModel
from fastapi import WebSocket
import uuid, time, hashlib, json
from pydantic import BaseModel

active_connections: dict[str, WebSocket] = {}
