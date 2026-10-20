from fastapi import APIRouter, HTTPException, Depends, Header
from app.main import state, get_api_key, is_minecraft_ready
from app.minecraft.stats import StatsResult, StatsErrorCode
from app.minecraft.connection import ConnectionStatus
from pydantic import BaseModel
from typing import Optional
import os
import asyncio
import time

router = APIRouter()

# API Key authentication dependency
async def verify_api_key(x_api_key: str = Header(None, alias="X-API-Key")):
    api_key = get_api_key()
    if not api_key:
        raise HTTPException(status_code=503, detail="API key not configured")
    if not x_api_key or x_api_key != api_key:
        raise HTTPException(status_code=401, detail="Invalid or missing API key")
    return True

@router.get("/health")
async def health():
    mc_state = None
    if state.mc_service and state.mc_service.connection_manager:
        mc_state = state.mc_service.connection_manager.get_state()
    connected = bool(mc_state and mc_state.status in (ConnectionStatus.LOGGED_IN, ConnectionStatus.SPAWNED))
    authenticated = bool(mc_state and mc_state.authenticated)
    return {"status": "ok", "minecraft_connected": connected, "authenticated": authenticated}

@router.get("/stats/{ign}")
async def get_stats(ign: str, authorized: bool = Depends(verify_api_key)):
    ign = ign.strip()
    if len(ign) < 3 or len(ign) > 16 or not all(c.isalnum() or c == '_' for c in ign):
        return {"success": False, "ign": ign, "uuid": None, "stats": {}, "source": "minecraft_inventory", "cached": False, "error": "Invalid username format"}
    if not await is_minecraft_ready():
        return {"success": False, "ign": ign, "uuid": None, "stats": {}, "source": "minecraft_inventory", "cached": False, "error": "The Minecraft client is not connected."}
    if state.cache:
        cached = await state.cache.get(ign)
        if cached:
            cached["cached"] = True
            return cached
    try:
        result = await state.request_queue.submit(ign, lambda i: state.mc_service.get_stats(i) if state.mc_service else None, correlation_id=f"stats_{ign}")
        if result is not None:
            return result
        return {"success": False, "ign": ign, "uuid": None, "stats": {}, "source": "minecraft_inventory", "cached": False, "error": "Request returned no result"}
    except asyncio.TimeoutError:
        return {"success": False, "ign": ign, "uuid": None, "stats": {}, "source": "minecraft_inventory", "cached": False, "error": "No response received before timeout"}
    except Exception as e:
        return {"success": False, "ign": ign, "uuid": None, "stats": {}, "source": "minecraft_inventory", "cached": False, "error": str(e)}
    return {"success": False, "ign": ign, "uuid": None, "stats": {}, "source": "minecraft_inventory", "cached": False, "error": "Unknown error during stats retrieval"}

@router.get("/connection")
async def get_connection(authorized: bool = Depends(verify_api_key)):
    conn_state = state.mc_service.connection_manager.get_state() if state.mc_service and state.mc_service.connection_manager else None
    if not conn_state:
        return {"connected": False, "authenticated": False, "server_host": state.settings.minecraft.server_host, "server_port": state.settings.minecraft.server_port, "uptime": 0, "last_disconnect": None}
    return {"connected": conn_state.connected, "authenticated": conn_state.authenticated, "logged_in": conn_state.logged_in, "spawned": conn_state.spawned, "server_host": conn_state.server_host, "server_port": conn_state.server_port, "uptime": int(conn_state.uptime), "last_disconnect": conn_state.last_disconnect, "last_error": conn_state.last_error, "player_name": conn_state.player_name, "player_uuid": conn_state.player_uuid, "reconnect_attempts": conn_state.reconnect_attempts}

@router.get("/metrics")
async def metrics(authorized: bool = Depends(verify_api_key)):
    return state.request_queue.get_metrics() if state.request_queue else {"error": "No metrics available"}
