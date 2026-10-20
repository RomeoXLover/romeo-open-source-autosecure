from typing import Optional, Dict, Any, Tuple
import asyncio
import time
import logging

logger = logging.getLogger(__name__)

class Cache:
    """
    Simple in-memory cache with TTL for stats results.
    
    Cache is optional - if cache_ttl is 0 or None, caching is disabled.
    """
    
    def __init__(self, ttl: Optional[float] = 300.0):
        self.ttl = ttl
        self._cache: Dict[str, Tuple[Any, float]] = {}
        self._lock = asyncio.Lock()
        
    async def get(self, key: str) -> Optional[Any]:
        """Get a cached value if not expired."""
        if not self.ttl:
            return None
            
        async with self._lock:
            if key in self._cache:
                value, timestamp = self._cache[key]
                if time.time() - timestamp < self.ttl:
                    return value
                else:
                    del self._cache[key]
        return None
        
    async def set(self, key: str, value: Any):
        """Set a cached value with current timestamp."""
        if not self.ttl:
            return
            
        async with self._lock:
            self._cache[key] = (value, time.time())
            
    async def cleanup(self):
        """Remove expired entries."""
        if not self.ttl:
            return
            
        now = time.time()
        async with self._lock:
            expired = [k for k, (_, ts) in self._cache.items() if now - ts >= self.ttl]
            for k in expired:
                del self._cache[k]
