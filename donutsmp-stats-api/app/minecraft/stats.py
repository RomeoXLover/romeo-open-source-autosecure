import asyncio
import json
import logging
import re
import time
from typing import Optional, Dict, Any, List
from dataclasses import dataclass
from enum import Enum

logger = logging.getLogger(__name__)

class StatsErrorCode(Enum):
    SUCCESS = "SUCCESS"
    INVALID_USERNAME = "INVALID_USERNAME"
    MINECRAFT_DISCONNECTED = "MINECRAFT_DISCONNECTED"
    COMMAND_DENIED = "COMMAND_DENIED"
    STATS_NOT_AVAILABLE = "STATS_NOT_AVAILABLE"
    UNSUPPORTED_INVENTORY = "UNSUPPORTED_INVENTORY"
    STATS_TIMEOUT = "STATS_TIMEOUT"
    SERVER_ERROR = "SERVER_ERROR"
    UNKNOWN_ERROR = "UNKNOWN_ERROR"

@dataclass
class StatsResult:
    success: bool
    ign: str
    uuid: Optional[str] = None
    stats: Dict[str, Any] = None
    source: str = "minecraft_inventory"
    cached: bool = False
    error: Optional[str] = None
    error_code: Optional[StatsErrorCode] = None

# Minecraft username validation per Mojang spec
USERNAME_PATTERN = re.compile(r'^[a-zA-Z0-9_]{3,16}$')

def validate_username(ign: str) -> bool:
    """Validate Minecraft username format."""
    if not ign or len(ign) < 3 or len(ign) > 16:
        return False
    return bool(USERNAME_PATTERN.match(ign))

class StatsRetriever:
    """
    Retrieves player statistics from DonutSMP using the Minecraft client.
    
    Workflow:
    1. Validate the requested username
    2. Confirm Minecraft client is connected and spawned
    3. Send "/stats IGN" command via chat
    4. Observe server response through chat packet listener
    5. Attempt to parse any inventory data (requires full protocol support)
    6. Return normalized JSON
    
    IMPORTANT LIMITATIONS:
    - The stripped PyCraft library (v0.7.0 from PyPI) does NOT include
      inventory/container window packets. It only has ChatMessagePacket
      for receiving output.
    - DonutSMP likely runs Minecraft 1.20.x, but PyCraft supports up to 1.19.4 (protocol 757).
    - The "/stats" command on DonutSMP opens a GUI inventory (verified behavior).
    - Without container packet support, we can only capture chat-based responses.
    
    This implementation captures chat responses from the stats command.
    Full inventory parsing requires a full-protocol library or the complete
    PyCraft development branch.
    """
    
    def __init__(self, connection_manager, timeout: float = 30.0):
        self.conn = connection_manager
        self.timeout = timeout
        self._chat_responses: List[Dict[str, Any]] = []
        self._response_event: Optional[asyncio.Event] = None
        self._listening: bool = False
        
    async def get_stats(self, ign: str) -> StatsResult:
        """Get player statistics by username."""
        # Step 1: Validate username
        if not validate_username(ign):
            return StatsResult(
                success=False,
                ign=ign,
                error="Invalid Minecraft username",
                error_code=StatsErrorCode.INVALID_USERNAME
            )
        
        # Step 2: Check connection
        if not self.conn.is_ready():
            return StatsResult(
                success=False,
                ign=ign,
                error="Minecraft client is not connected or spawned",
                error_code=StatsErrorCode.MINECRAFT_DISCONNECTED
            )
        
        try:
            # Step 3: Set up response listener and send command
            self._response_event = asyncio.Event()
            self._chat_responses.clear()
            self._listening = True
            
            # Send the stats command
            cmd = f"/stats {ign}"
            logger.info(f"Sending command: {cmd}")
            
            if not self.conn.send_chat(cmd):
                return StatsResult(
                    success=False,
                    ign=ign,
                    error="Failed to send stats command",
                    error_code=StatsErrorCode.UNKNOWN_ERROR
                )
            
            # Step 4-5: Wait for response with timeout
            try:
                await asyncio.wait_for(self._response_event.wait(), timeout=self.timeout)
            except asyncio.TimeoutError:
                self._listening = False
                return StatsResult(
                    success=False,
                    ign=ign,
                    error="No response received before timeout",
                    error_code=StatsErrorCode.STATS_TIMEOUT
                )
            
            self._listening = False
            
            # Step 6: Parse response
            if not self._chat_responses:
                return StatsResult(
                    success=False,
                    ign=ign,
                    error="No chat response captured",
                    error_code=StatsErrorCode.STATS_NOT_AVAILABLE
                )
            
            # Parse chat responses for stats info
            stats = self._parse_chat_responses(ign)
            
            if not stats:
                return StatsResult(
                    success=False,
                    ign=ign,
                    error="Could not parse stats from server response",
                    error_code=StatsErrorCode.UNSUPPORTED_INVENTORY
                )
            
            return StatsResult(
                success=True,
                ign=ign,
                stats=stats,
                source="minecraft_chat"
            )
            
        except Exception as e:
            logger.error(f"Stats retrieval error: {e}", exc_info=True)
            return StatsResult(
                success=False,
                ign=ign,
                error=str(e),
                error_code=StatsErrorCode.UNKNOWN_ERROR
            )
    
    def capture_chat_response(self, json_data: str):
        """Called by connection manager when chat is received."""
        if not self._listening:
            return
            
        try:
            data = json.loads(json_data)
            self._chat_responses.append(data)
            
            # Check for common "not found" or "denied" responses
            text = self._extract_text(data)
            if text:
                if "not found" in text.lower() or "doesn't exist" in text.lower():
                    self._response_event.set()
                elif "no permission" in text.lower() or "denied" in text.lower():
                    self._response_event.set()
                else:
                    # Got some response, check if it looks like stats
                    self._response_event.set()
                    
        except (json.JSONDecodeError, KeyError):
            pass
    
    def _extract_text(self, chat_data: Dict) -> str:
        """Extract text from Minecraft chat JSON format."""
        if isinstance(chat_data, str):
            return chat_data
        if isinstance(chat_data, dict):
            text = chat_data.get('text', '')
            extra = chat_data.get('extra', [])
            if isinstance(extra, list):
                for item in extra:
                    if isinstance(item, dict):
                        text += item.get('text', '')
                    elif isinstance(item, str):
                        text += item
            return text
        return ''
    
    def _parse_chat_responses(self, ign: str) -> Optional[Dict[str, Any]]:
        """
        Parse chat responses to extract stats information.
        
        This is a basic parser. The actual DonutSMP stats command may return
        formatted text with player info, online status, and kill/death stats.
        
        Returns None if parsing fails or response indicates error.
        """
        for resp in self._chat_responses:
            text = self._extract_text(resp)
            
            # Check for error responses
            lower = text.lower()
            if 'not found' in lower or 'doesn\'t exist' in lower:
                return None
            if 'no permission' in lower or 'denied' in lower:
                return None
                
            # Check for stats content
            # DonutSMP stats typically return: "IGN is online/offline | Kills: X | Deaths: Y | K/D: Z"
            if ign.lower() in lower or 'kills' in lower or 'kd' in lower:
                return self._parse_stats_text(text, ign)
                
        return None
    
    def _parse_stats_text(self, text: str, ign: str) -> Optional[Dict[str, Any]]:
        """Parse the actual stats text from chat response."""
        stats = {
            "ign": ign,
            "raw": text
        }
        
        # Try to extract common patterns
        # Format may vary - this is a best-effort parse
        patterns = {
            'kills': r'[Kk]ills?:?\s*(\d+)',
            'deaths': r'[Dd]eaths?:?\s*(\d+)',
            'kd': r'[K\/]D:?\s*([\d.]+)',
            'online': r'(online|offline)',
            'playtime': r'[Pp]lay[tT]ime:?\s*([\d\s\w]+)',
            'rank': r'[Rr]ank:?\s*(\w+)'
        }
        
        for key, pattern in patterns.items():
            match = re.search(pattern, text)
            if match:
                stats[key] = match.group(1)
                
        return stats if len(stats) > 1 else None
