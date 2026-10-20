from fastapi import APIRouter, HTTPException, Depends
from app import get_db, verify_token
import json

router = APIRouter()

@router.get("/api/user/summary")
async def get_summary(user: str = Depends(verify_token)):
    conn = get_db()
    accounts = conn.execute("SELECT COUNT(*) as c FROM romeo_users").fetchone()["c"]
    bots = conn.execute("SELECT COUNT(*) as c FROM romeo_bots").fetchone()["c"]
    conn.close()
    return {
        "success": True,
        "data": {
            "total_accounts": accounts,
            "total_bots": bots,
            "net_worth": 1500000000,
            "shared_links": 12,
            "avg_value": 5000000,
            "bots_online": 3
        },
        "http_status": 200
    }

@router.get("/api/user/analytics")
async def get_analytics(user: str = Depends(verify_token)):
    return {"success": True, "history": [{"date": "2025-01-01", "secures": 5}], "recent": [], "http_status": 200}

@router.get("/api/user/stats")
async def get_stats(user: str = Depends(verify_token)):
    return {"success": True, "stats": {"total_secures": 150, "success_rate": 95.2, "avg_time": 45}, "http_status": 200}

@router.get("/api/v1/history")
async def get_history(user: str = Depends(verify_token)):
    return {"success": True, "history": [{"date": "2025-01-01", "count": 5}], "http_status": 200}

@router.get("/api/user/accounts")
async def list_accounts(user: str = Depends(verify_token), search: str = "", sort: str = "newest", page: int = 1):
    conn = get_db()
    rows = conn.execute("SELECT * FROM romeo_users LIMIT 20 OFFSET ?", ((page-1)*20,)).fetchall()
    conn.close()
    return {"success": True, "accounts": [dict(r) for r in rows], "page": page, "http_status": 200}

@router.get("/api/user/bots")
async def user_bots(user: str = Depends(verify_token)):
    conn = get_db()
    rows = conn.execute("SELECT * FROM romeo_bots").fetchall()
    conn.close()
    return {"success": True, "bots": [dict(r) for r in rows], "http_status": 200}
