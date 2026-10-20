from app.config import Settings, get_session_token
from app.minecraft.connection import ConnectionManager, ConnectionStatus
from app.minecraft.stats import StatsRetriever, StatsResult
from app.minecraft.movement import MovementManager, AntiAfkManager
import asyncio
import logging

logger = logging.getLogger(__name__)

class MinecraftService:
    """Service layer for Minecraft operations."""
    
    def __init__(self, settings: Settings):
        self.settings = settings
        self.connection_manager: ConnectionManager = None
        self.stats_retriever: StatsRetriever = None
        self.movement: MovementManager = None
        self.anti_afk: AntiAfkManager = None
        self._initialized = False
        
    async def initialize(self):
        """Initialize Minecraft connection components."""
        if self._initialized:
            return
            
        session_token = get_session_token(self.settings)
        if not session_token:
            logger.error(f"Session token not found in env: {self.settings.minecraft.session_token_env}")
            self._initialized = True
            return
            
        self.connection_manager = ConnectionManager(
            host=self.settings.minecraft.server_host,
            port=self.settings.minecraft.server_port,
            username=self.settings.minecraft.username or "Bot",
            session_token=session_token,
            auth_method=self.settings.minecraft.auth_method
        )
        
        self.stats_retriever = StatsRetriever(
            self.connection_manager,
            timeout=self.settings.api.request_timeout_seconds
        )
        
        self.movement = MovementManager(
            self.connection_manager,
            enabled=self.settings.movement.enabled,
            duration=self.settings.movement.forward_seconds
        )
        
        self.anti_afk = AntiAfkManager(
            self.connection_manager,
            enabled=self.settings.anti_afk.enabled,
            interval=self.settings.anti_afk.interval_seconds
        )
        
        self._initialized = True
        
    async def connect(self):
        """Connect to Minecraft server."""
        if not self.connection_manager:
            logger.error("Connection manager not initialized")
            return False
        return await self.connection_manager.connect(reconnect=self.settings.minecraft.reconnect)
        
    async def disconnect(self):
        """Disconnect from Minecraft server."""
        if self.connection_manager:
            await self.connection_manager.disconnect()
            
    async def start_movement(self):
        """Start initial movement if enabled."""
        if self.movement and self.movement.enabled:
            await self.movement.start_initial_movement()
            
    async def start_anti_afk(self):
        """Start anti-AFK if enabled."""
        if self.anti_afk and self.anti_afk.enabled:
            await self.anti_afk.start()
            
    async def get_stats(self, ign: str) -> StatsResult:
        """Get player statistics."""
        if not self.stats_retriever:
            return StatsResult(
                success=False,
                ign=ign,
                error="Minecraft service not initialized"
            )
        return await self.stats_retriever.get_stats(ign)
        
    def get_connection_state(self):
        """Get current connection state."""
        if not self.connection_manager:
            return None
        return self.connection_manager.get_state()
        
    def is_healthy(self) -> bool:
        """Check if Minecraft connection is healthy."""
        if not self.connection_manager:
            return False
        state = self.connection_manager.get_state()
        return state.status in (ConnectionStatus.LOGGED_IN, ConnectionStatus.SPAWNED)
