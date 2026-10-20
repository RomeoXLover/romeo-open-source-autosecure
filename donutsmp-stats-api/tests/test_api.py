"""Tests for API endpoints."""
import pytest
import os
import asyncio

os.environ['STATS_API_KEY'] = 'test-key-123'
os.environ['MINECRAFT_SESSION_TOKEN'] = 'fake-token-for-testing'

from fastapi.testclient import TestClient
from app.config import load_config
from app.main import initialize_app, state
from app.api.main import app

@pytest.fixture(scope="module")
def client():
    async def setup():
        settings = load_config()
        await initialize_app(settings)
    
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    loop.run_until_complete(setup())
    
    state.api_key = 'test-key-123'
    
    with TestClient(app) as c:
        yield c

@pytest.fixture
def api_headers():
    return {"X-API-Key": "test-key-123"}

class TestHealthEndpoint:
    def test_health(self, client):
        resp = client.get("/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ok"
        assert "minecraft_connected" in data
        assert "authenticated" in data

class TestStatsEndpoint:
    def test_stats_requires_api_key(self, client):
        resp = client.get("/stats/test")
        assert resp.status_code == 401
        
    def test_stats_invalid_api_key(self, client):
        resp = client.get("/stats/test", headers={"X-API-Key": "wrong"})
        assert resp.status_code == 401
        
    def test_stats_invalid_username(self, client, api_headers):
        resp = client.get("/stats/a", headers=api_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert data["success"] == False
        assert "Invalid username" in data["error"]
        
    def test_stats_no_connection(self, client, api_headers):
        resp = client.get("/stats/ValidPlayer", headers=api_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert data["success"] == False
        assert "not connected" in data["error"].lower()

class TestConnectionEndpoint:
    def test_connection_requires_api_key(self, client):
        resp = client.get("/connection")
        assert resp.status_code == 401
        
    def test_connection_info(self, client, api_headers):
        resp = client.get("/connection", headers=api_headers)
        assert resp.status_code == 200
        data = resp.json()
        # connected may be True if MC client connected, False if not
        assert "connected" in data
        assert data["server_host"] == "donutsmp.net"

class TestMetricsEndpoint:
    def test_metrics_requires_api_key(self, client):
        resp = client.get("/metrics")
        assert resp.status_code == 401
        
    def test_metrics(self, client, api_headers):
        resp = client.get("/metrics", headers=api_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert "total_requests" in data
        assert "success_rate" in data
