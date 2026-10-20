from pydantic import BaseModel, Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict
from typing import Optional
import json
import os

class MinecraftConfig(BaseModel):
    server_host: str = "donutsmp.net"
    server_port: int = 25565
    auth_method: str = "microsoft"
    username: str = ""
    session_token_env: str = "MINECRAFT_SESSION_TOKEN"
    proxy_enabled: bool = False
    proxy_url: str = ""
    reconnect: bool = True
    
    @field_validator('server_port')
    @classmethod
    def validate_port(cls, v):
        if not (1 <= v <= 65535):
            raise ValueError('Port must be between 1 and 65535')
        return v
    
    @field_validator('proxy_url')
    @classmethod
    def validate_proxy(cls, v):
        if v:
            if not v.startswith(('socks5://', 'socks4://', 'http://')):
                raise ValueError('Proxy URL must start with socks5://, socks4://, or http://')
        return v

class MovementConfig(BaseModel):
    enabled: bool = False
    forward_seconds: int = 3

class AntiAfkConfig(BaseModel):
    enabled: bool = False
    interval_seconds: int = 60

class ApiConfig(BaseModel):
    host: str = "127.0.0.1"
    port: int = 8000
    api_key_env: str = "STATS_API_KEY"
    request_timeout_seconds: int = 30
    
    @field_validator('port')
    @classmethod
    def validate_port(cls, v):
        if not (1 <= v <= 65535):
            raise ValueError('Port must be between 1 and 65535')
        return v

class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")
    
    minecraft: MinecraftConfig = MinecraftConfig()
    movement: MovementConfig = MovementConfig()
    anti_afk: AntiAfkConfig = AntiAfkConfig()
    api: ApiConfig = ApiConfig()
    
    @classmethod
    def from_json(cls, path: str = "config.json") -> "Settings":
        data = {}
        if os.path.exists(path):
            with open(path, 'r') as f:
                data = json.load(f)
        return cls(**data)

def load_config() -> Settings:
    """Load configuration from config.json with .env overrides."""
    settings = Settings.from_json()
    return settings

def get_session_token(settings: Settings) -> Optional[str]:
    """Get session token from environment variable."""
    env_var = settings.minecraft.session_token_env
    token = os.environ.get(env_var)
    return token

def validate_config(settings: Settings) -> list[str]:
    """Validate configuration and return list of errors."""
    errors = []
    
    if not settings.minecraft.server_host:
        errors.append("minecraft.server_host is required")
    
    token = get_session_token(settings)
    if settings.minecraft.auth_method == "microsoft" and not token:
        errors.append(f"Minecraft session token not found in env var: {settings.minecraft.session_token_env}")
    
    api_key = os.environ.get(settings.api.api_key_env)
    if not api_key:
        errors.append(f"API key not found in env var: {settings.api.api_key_env}")
    
    if settings.minecraft.proxy_enabled and not settings.minecraft.proxy_url:
        errors.append("Proxy enabled but no proxy_url configured")
    
    return errors
