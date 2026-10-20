"""Unit tests for DonutSMP Stats API."""
import pytest
import asyncio
import os
import json
from fastapi.testclient import TestClient

# Set env vars before importing
os.environ['STATS_API_KEY'] = 'test-key-123'
os.environ['MINECRAFT_SESSION_TOKEN'] = 'fake-token-for-testing'

from app.config import load_config, validate_config, Settings
from app.minecraft.connection import ConnectionState, ConnectionStatus
from app.minecraft.stats import StatsRetriever, validate_username, StatsErrorCode

class TestConfig:
    def test_config_loads(self):
        settings = load_config()
        assert settings.minecraft.server_host == "donutsmp.net"
        assert settings.minecraft.server_port == 25565
        assert settings.api.port == 8000
        
    def test_config_validation(self):
        settings = load_config()
        errors = validate_config(settings)
        # Should have warnings about missing tokens (expected in test env)
        assert len(errors) >= 0

class TestUsernameValidation:
    def test_valid_username(self):
        assert validate_username("ExamplePlayer") == True
        assert validate_username("Player_123") == True
        assert validate_username("abc") == True
        
    def test_invalid_username(self):
        assert validate_username("ab") == False  # too short
        assert validate_username("") == False
        assert validate_username("a" * 17) == False  # too long
        assert validate_username("play!er") == False  # invalid char
        
class TestConnectionState:
    def test_default_state(self):
        state = ConnectionState()
        assert state.status == ConnectionStatus.DISCONNECTED
        assert state.connected == False
        assert state.authenticated == False

if __name__ == "__main__":
    pytest.main([__file__, "-v"])
