import asyncio
import logging
import time
from typing import Optional
from dataclasses import dataclass

logger = logging.getLogger(__name__)

class MovementManager:
    """
    Optional movement controller for initial connection setup.
    
    Movement is DISABLED by default. Only enable when:
    - The server permits movement (not anti-cheat protected)
    - User has explicitly set movement.enabled=true in config
    
    Movement packets alone do NOT prevent AFK detection on modern servers.
    """
    
    def __init__(self, connection_manager, enabled: bool = False, duration: int = 3):
        self.conn = connection_manager
        self.enabled = enabled
        self.duration = duration
        self._task: Optional[asyncio.Task] = None
        
    async def start_initial_movement(self):
        """Perform initial movement to ensure full spawn."""
        if not self.enabled or not self.conn.is_ready():
            return
            
        if self._task and not self._task.done():
            self._task.cancel()
            
        self._task = asyncio.create_task(self._movement_loop())
        
    async def _movement_loop(self):
        """Move forward for configured duration then stop."""
        start = time.time()
        while time.time() - start < self.duration:
            if not self.conn.is_ready():
                break
                
            try:
                # Send forward movement packet
                from minecraft.networking.packets.serverbound.play import PositionAndLookPacket
                packet = PositionAndLookPacket(self.conn.connection.context)
                # Move slightly forward, stay on ground
                if hasattr(packet, 'on_ground'):
                    packet.on_ground = True
                self.conn.connection.write_packet(packet)
            except Exception as e:
                logger.debug(f"Movement packet error: {e}")
                break
                
            await asyncio.sleep(0.1)
            
        logger.info(f"Movement completed after {self.duration}s")
        
    async def stop(self):
        """Stop movement."""
        if self._task and not self._task.done():
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass

class AntiAfkManager:
    """
    Optional AFK prevention. DISABLED by default.
    
    IMPORTANT: This module is intentionally simple and does not implement
    anti-anti-cheat evasion mechanisms. DonutSMP may have AFK kick timers
    that movement alone cannot bypass.
    """
    
    def __init__(self, connection_manager, enabled: bool = False, interval: int = 60):
        self.conn = connection_manager
        self.enabled = enabled
        self.interval = interval
        self._task: Optional[asyncio.Task] = None
        
    async def start(self):
        """Start the AFK prevention loop."""
        if not self.enabled:
            return
            
        self._task = asyncio.create_task(self._afk_loop())
        
    async def _afk_loop(self):
        """Simple periodic movement to stay active."""
        while True:
            await asyncio.sleep(self.interval)
            if not self.conn.is_ready():
                continue
                
            try:
                # Send a simple position update to keep session active
                from minecraft.networking.packets.serverbound.play import PositionAndLookPacket
                packet = PositionAndLookPacket(self.conn.connection.context)
                packet.on_ground = True
                self.conn.connection.write_packet(packet)
                logger.debug("AFK movement sent")
            except Exception as e:
                logger.debug(f"AFK movement error: {e}")
                
    async def stop(self):
        """Stop the AFK loop."""
        if self._task and not self._task.done():
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
