from app.config import Settings, get_session_token
from app.minecraft.service import MinecraftService
from app.minecraft.connection import ConnectionStatus
from app.services.request_queue import RequestQueue
from app.services.cache import Cache
import asyncio
import logging
import os
import time

logger = logging.getLogger(__name__)

class ApplicationState:
    """Global application state shared across requests."""
    
    def __init__(self):
        self.settings: Settings = None
        self.mc_service: MinecraftService = None
        self.request_queue: RequestQueue = None
        self.cache: Cache = None
        self.start_time: float = time.time()
        self.api_key: str = None
        self.initialized: bool = False

state = ApplicationState()

async def initialize_app(settings: Settings):
    """Initialize the application with Minecraft connection."""
    state.settings = settings
    
    # Validate config
    errors = validate_config(settings)
    if errors:
        for err in errors:
            logger.warning(f"Config warning: {err}")
    
    # Initialize cache
    state.cache = Cache(ttl=300.0)  # 5 minutes
    
    # Initialize request queue
    state.request_queue = RequestQueue(
        timeout=settings.api.request_timeout_seconds,
        cache_ttl=300.0
    )
    
    # Get API key
    api_key = os.environ.get(settings.api.api_key_env)
    if api_key:
        state.api_key = api_key
    
    # Initialize Minecraft service
    state.mc_service = MinecraftService(settings)
    await state.mc_service.initialize()
    
    # Connect if session token available
    if os.environ.get(settings.minecraft.session_token_env):
        asyncio.create_task(state.mc_service.connect())
    
    # Start queue processor
    asyncio.create_task(
        state.request_queue.process(
            state.mc_service.connection_manager,
            state.mc_service.stats_retriever if state.mc_service.stats_retriever else None
        )
    )
    
    state.initialized = True
    logger.info("Application initialized")

async def shutdown_app():
    """Shutdown the application."""
    if state.mc_service:
        await state.mc_service.disconnect()
        
    if state.request_queue:
        await state.request_queue.stop()
        
    logger.info("Application shut down")

def get_connection_state():
    """Get current Minecraft connection state."""
    if not state.mc_service or not state.mc_service.connection_manager:
        return None
    return state.mc_service.connection_manager.get_state()

def get_metrics():
    """Get application metrics."""
    metrics = state.request_queue.get_metrics() if state.request_queue else {}
    metrics['uptime_seconds'] = int(time.time() - state.start_time) if state.start_time else 0
    return metrics

def get_api_key() -> str:
    """Get API key from settings."""
    if not state.api_key and state.settings:
        state.api_key = os.environ.get(state.settings.api.api_key_env)
    return state.api_key

async def is_minecraft_ready() -> bool:
    """Check if Minecraft is connected and ready."""
    if not state.mc_service:
        return False
    return state.mc_service.is_healthy()

from app.config import validate_config
