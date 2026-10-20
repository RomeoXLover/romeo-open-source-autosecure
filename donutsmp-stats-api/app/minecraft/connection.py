import asyncio
import logging
import time
from enum import Enum
from typing import Optional, Any
from dataclasses import dataclass, field
from minecraft.authentication import AuthenticationToken
from minecraft.networking.connection import Connection

logger = logging.getLogger(__name__)

class ConnectionStatus(Enum):
    DISCONNECTED = "disconnected"
    CONNECTING = "connecting"
    CONNECTED = "connected"
    LOGGED_IN = "logged_in"
    SPAWNED = "spawned"
    ERROR = "error"
    RECONNECTING = "reconnecting"

@dataclass
class ConnectionState:
    status: ConnectionStatus = ConnectionStatus.DISCONNECTED
    connected: bool = False
    authenticated: bool = False
    logged_in: bool = False
    spawned: bool = False
    server_host: str = ""
    server_port: int = 0
    uptime: float = 0.0
    last_disconnect: Optional[str] = None
    last_error: Optional[str] = None
    reconnect_attempts: int = 0
    start_time: float = field(default_factory=time.time)
    player_uuid: Optional[str] = None
    player_name: Optional[str] = None

class MinecraftAuthError(Exception):
    """Raised when Minecraft authentication fails."""
    pass

class ConnectionManager:
    """
    Manages Minecraft connection lifecycle with PyCraft.
    
    Authentication methods supported:
    - Microsoft: Uses AuthenticationToken with access_token (Xbox/MSA refresh token flow)
    - Yggdrasil: Uses AuthenticationToken.authenticate(username, password)
    
    Note: The session_token is a Microsoft/Xbox access token obtained via OAuth2.
    It is NOT an SSID (session server ID). The AuthenticationToken.join() method
    converts the authenticated token to a session server token.
    
    Auth flow:
    1. AuthenticationToken(authenticated=True, username=name, access_token=token)
    2. token = auth_token.access_token  (the Yggdrasil/Microsoft access token)
    3. Connection(address, port, auth_token=auth_token) then connect()
    """
    
    def __init__(self, host: str, port: int, username: str, session_token: str, 
                 auth_method: str = "microsoft"):
        self.host = host
        self.port = port
        self.username = username
        self.session_token = session_token
        self.auth_method = auth_method
        self.connection: Optional[Connection] = None
        self.state = ConnectionState(
            server_host=host,
            server_port=port
        )
        self._lock = asyncio.Lock()
        self._connect_task: Optional[asyncio.Task] = None
        self._connection_ready: asyncio.Event = None
        
    async def connect(self, reconnect: bool = True) -> bool:
        """Connect to Minecraft server with authentication."""
        async with self._lock:
            if self._connect_task and not self._connect_task.done():
                logger.warning("Connection loop already running")
                return False
                
            self._connection_ready = asyncio.Event()
            self._connect_task = asyncio.create_task(self._connect_loop(reconnect))
            
            try:
                await asyncio.wait_for(self._connection_ready.wait(), timeout=30.0)
            except asyncio.TimeoutError:
                logger.error("Connection timed out")
                return False
                
            return self.state.connected
            
    async def _connect_loop(self, allow_reconnect: bool):
        """Main connection loop with backoff reconnection."""
        backoff = 1.0
        max_backoff = 60.0
        
        while True:
            try:
                self.state.status = ConnectionStatus.CONNECTING
                self.state.reconnect_attempts = 0
                
                # Create authentication token
                # session_token is a Microsoft/Xbox access token (NOT an SSID)
                # AuthenticationToken expects: username, access_token pair
                auth_token = AuthenticationToken()
                auth_token.username = self.username
                auth_token.access_token = self.session_token
                auth_token.client_token = None
                auth_token._profile = None
                
                # Connect using PyCraft
                self.connection = Connection(
                    address=self.host,
                    port=self.port,
                    auth_token=auth_token,
                    username=self.username,
                    initial_version=None  # Auto-detect
                )
                
                # Register packet listeners
                self._register_listeners()
                
                # Set up the connection
                self.connection.connect()
                
                # Wait for login to complete
                self.state.status = ConnectionStatus.CONNECTED
                self.state.connected = True
                self.state.authenticated = True
                self._connection_ready.set()
                
                logger.info(f"Connected to {self.host}:{self.port} as {self.username}")
                
                # Reset backoff on successful connection
                backoff = 1.0
                
                # Stay connected until disconnected
                while self.connection and self.connection.connected:
                    await asyncio.sleep(1)
                    self.state.uptime += 1
                    
            except Exception as e:
                logger.error(f"Connection error: {e}", exc_info=True)
                self.state.last_error = str(e)
                
                if not self._connection_ready.is_set():
                    self._connection_ready.set()
                    
                self.state.connected = False
                self.state.authenticated = False
                self.state.status = ConnectionStatus.ERROR
                
                if not allow_reconnect:
                    break
                    
                if self.state.status == ConnectionStatus.ERROR:
                    logger.info(f"Reconnecting in {backoff}s...")
                    self.state.status = ConnectionStatus.RECONNECTING
                    time.sleep(backoff)
                    backoff = min(backoff * 1.5, max_backoff)
                    
    def _register_listeners(self):
        """Register packet listeners on the connection."""
        from minecraft.networking.packets.clientbound.play import (
            ChatMessagePacket, JoinGamePacket, PlayerPositionAndLookPacket
        )
        
        @self.connection.listener(ChatMessagePacket)
        def handle_chat(packet, conn):
            json_data = packet.json_data
            logger.info(f"Chat: {json_data}")
            
        @self.connection.listener(JoinGamePacket)
        def handle_join(packet, conn):
            self.state.logged_in = True
            self.state.player_uuid = packet.player_UUID
            logger.info(f"Joined game as {packet.username}")
            
        @self.connection.listener(PlayerPositionAndLookPacket)
        def handle_position(packet, conn):
            self.state.spawned = True
            logger.info(f"Player spawned at {packet.x}, {packet.y}, {packet.z}")
    
    async def disconnect(self):
        """Gracefully disconnect from Minecraft server."""
        async with self._lock:
            if self._connect_task and not self._connect_task.done():
                self._connect_task.cancel()
                try:
                    await self._connect_task
                except asyncio.CancelledError:
                    pass
                    
            if self.connection:
                try:
                    self.connection.disconnect(immediate=True)
                except Exception as e:
                    logger.warning(f"Error during disconnect: {e}")
                    
            self.state.connected = False
            self.state.authenticated = False
            self.state.logged_in = False
            self.state.spawned = False
            self.state.status = ConnectionStatus.DISCONNECTED
            
    def get_state(self) -> ConnectionState:
        """Get current connection state."""
        if self.state.connected:
            self.state.uptime = time.time() - self.state.start_time
        return self.state
        
    def send_chat(self, message: str) -> bool:
        """Send a chat/command message to the server."""
        if not self.connection or not self.connection.connected:
            return False
            
        try:
            from minecraft.networking.packets.serverbound.play import ChatPacket
            packet = ChatPacket(self.connection.context)
            packet.message = message
            self.connection.send_packet(packet)
            return True
        except Exception as e:
            logger.error(f"Failed to send chat: {e}")
            return False
    
    def is_ready(self) -> bool:
        """Check if client is spawned and ready for interaction."""
        return self.state.spawned and self.connection is not None and self.connection.connected