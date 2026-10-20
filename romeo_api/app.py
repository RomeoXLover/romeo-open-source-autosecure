from fastapi import FastAPI, HTTPException, Depends, Request, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import sqlite3, json, os, hmac, hashlib, secrets, time
import jwt

DB_PATH = os.environ.get("STEN_DB", "/root/romeoopen/extracted/db/database.db")
JWT_SECRET = secrets.token_hex(32)
ALGO = "HS256"
RATE_LIMIT = {"requests": {}, "limit": 100, "window": 60}

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = get_db()
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS romeo_api_keys (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id TEXT NOT NULL,
            key_hash TEXT UNIQUE NOT NULL,
            key_display TEXT NOT NULL,
            ws_access INTEGER DEFAULT 0,
            created_at REAL DEFAULT (strftime('%s','now'))
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS romeo_users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            discord_id TEXT UNIQUE,
            username TEXT,
            email TEXT,
            password TEXT,
            totp_secret TEXT,
            role TEXT DEFAULT 'user',
            license_key TEXT,
            bot_slots INTEGER DEFAULT 1,
            links_days INTEGER DEFAULT 0,
            show_leaderboard INTEGER DEFAULT 1,
            created_at REAL DEFAULT (strftime('%s','now'))
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS romeo_bots (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id TEXT NOT NULL,
            bot_index INTEGER,
            bot_name TEXT,
            bot_id TEXT,
            token TEXT,
            status TEXT DEFAULT 'offline',
            ping INTEGER,
            uptime INTEGER,
            last_seen REAL,
            created_at REAL DEFAULT (strftime('%s','now'))
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS romeo_links (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id TEXT,
            bot_index INTEGER,
            code TEXT UNIQUE,
            type TEXT,
            cosmetic TEXT,
            price REAL,
            expires_at REAL,
            created_at REAL DEFAULT (strftime('%s','now'))
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS romeo_sessions (
            id TEXT PRIMARY KEY,
            user_id TEXT,
            bot_index INTEGER,
            email TEXT,
            username TEXT,
            uuid TEXT,
            no_password INTEGER DEFAULT 0,
            ip TEXT,
            stage TEXT,
            custom_values TEXT,
            expires_at REAL,
            created_at REAL DEFAULT (strftime('%s','now'))
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS romeo_audit (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id TEXT,
            bot_id TEXT,
            action TEXT,
            details TEXT,
            ip_address TEXT,
            created_at REAL DEFAULT (strftime('%s','now'))
        )
    """)
    conn.commit()
    conn.close()

init_db()

app = FastAPI(title="romeo.wtf API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

def verify_api_key(request: Request) -> dict:
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        raise HTTPException(401, "missing_api_key")
    token = auth[7:]
    key_hash = hashlib.sha256(token.encode()).hexdigest()
    conn = get_db()
    row = conn.execute("SELECT * FROM romeo_api_keys WHERE key_hash = ?", (key_hash,)).fetchone()
    conn.close()
    if not row:
        raise HTTPException(401, "invalid_api_key")
    return dict(row)

def issue_token(user_id: str) -> str:
    now = int(time.time())
    return jwt.encode({"sub": user_id, "iat": now, "exp": now + 8*3600}, JWT_SECRET, algorithm=ALGO)

def verify_token(request: Request) -> str:
    token = request.cookies.get("session")
    if not token:
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            raise HTTPException(401, "not_authenticated")
        token = auth[7:]
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[ALGO])
        return payload["sub"]
    except Exception:
        raise HTTPException(401, "invalid_or_expired_session")

def rate_limit_check(user_id: str) -> bool:
    now = time.time()
    key = f"{user_id}"
    if key not in RATE_LIMIT["requests"]:
        RATE_LIMIT["requests"][key] = []
    RATE_LIMIT["requests"][key] = [t for t in RATE_LIMIT["requests"][key] if now - t < RATE_LIMIT["window"]]
    if len(RATE_LIMIT["requests"][key]) >= RATE_LIMIT["limit"]:
        return False
    RATE_LIMIT["requests"][key].append(now)
    return True

from routers.auth import router as auth_router
from routers.accounts import router as accounts_router
from routers.bots import router as bots_router
from routers.secure import router as secure_router
from routers.beam import router as beam_router
from routers.user import router as user_router
from routers.websocket import router as ws_router, websocket_endpoint

app.include_router(auth_router)
app.include_router(accounts_router)
app.include_router(bots_router)
app.include_router(secure_router)
app.include_router(beam_router)
app.include_router(user_router)
app.add_route("/api/", websocket_endpoint, methods=["GET"])
