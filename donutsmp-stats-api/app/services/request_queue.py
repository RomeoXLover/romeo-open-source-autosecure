from app.minecraft.connection import ConnectionStatus
import asyncio
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Optional, Dict, Any
import logging

logger = logging.getLogger(__name__)

@dataclass
class RequestEntry:
    ign: str
    request_id: str
    timestamp: float
    future: asyncio.Future

@dataclass
class Metrics:
    total_requests: int = 0
    successful_requests: int = 0
    failed_requests: int = 0
    total_latency_ms: float = 0.0
    cache_hits: int = 0
    cache_misses: int = 0
    
    @property
    def avg_latency_ms(self) -> float:
        if self.successful_requests == 0:
            return 0.0
        return self.total_latency_ms / self.successful_requests
    
    @property
    def success_rate(self) -> float:
        if self.total_requests == 0:
            return 0.0
        return (self.successful_requests / self.total_requests) * 100

class RequestQueue:
    """
    Asyncio request queue for Minecraft stats operations.
    
    Since a single Minecraft connection cannot safely process multiple
    GUI/command requests simultaneously, this queue serializes operations.
    
    Features:
    - Single active stats operation per Minecraft connection
    - Configurable queue timeout
    - Request correlation via request_id
    - Lock around GUI operations
    - Cleanup on timeout/disconnect
    """
    
    def __init__(self, timeout: float = 60.0, cache_ttl: Optional[float] = None):
        self.timeout = timeout
        self.cache_ttl = cache_ttl
        self._queue: asyncio.Queue = asyncio.Queue()
        self._lock = asyncio.Lock()
        self._active_request: Optional[RequestEntry] = None
        self._cache: Dict[str, tuple] = {}  # ign -> (result, timestamp)
        self._metrics = Metrics()
        self._running = True
        
    async def submit(self, ign: str, fetch_func, correlation_id: str = None) -> Any:
        """Submit a stats request to the queue."""
        import uuid
        request_id = correlation_id or str(uuid.uuid4())
        
        # Check cache
        cached_result = self._get_cached(ign)
        if cached_result is not None:
            self._metrics.cache_hits += 1
            return cached_result
            
        self._metrics.cache_misses += 1
        
        # Create future for response
        future = asyncio.get_event_loop().create_future()
        entry = RequestEntry(ign=ign, request_id=request_id, timestamp=time.time(), future=future)
        
        # Queue the request
        await self._queue.put(entry)
        self._metrics.total_requests += 1
        
        try:
            result = await asyncio.wait_for(future, timeout=self.timeout)
            return result
        except asyncio.TimeoutError:
            self._metrics.failed_requests += 1
            raise TimeoutError(f"Stats request timed out for {ign}")
            
    async def process(self, conn_manager, stats_retriever):
        """Process queued requests one at a time."""
        while self._running:
            try:
                entry = await self._queue.get()
                
                async with self._lock:
                    if not conn_manager.is_ready():
                        entry.future.set_result({
                            "success": False,
                            "ign": entry.ign,
                            "error": "Minecraft client not connected"
                        })
                        continue
                        
                    start_time = time.time()
                    try:
                        result = await stats_retriever.get_stats(entry.ign)
                        latency = (time.time() - start_time) * 1000
                        
                        self._metrics.successful_requests += 1
                        self._metrics.total_latency_ms += latency
                        
                        # Cache the result
                        if self.cache_ttl and result.success:
                            self._cache[entry.ign] = (result, time.time())
                        
                        entry.future.set_result({
                            "success": result.success,
                            "ign": result.ign,
                            "uuid": result.uuid,
                            "stats": result.stats,
                            "source": result.source,
                            "cached": False,
                            "error": result.error,
                            "error_code": result.error_code.value if result.error_code else None,
                            "latency_ms": round(latency, 2)
                        })
                        
                    except Exception as e:
                        self._metrics.failed_requests += 1
                        entry.future.set_result({
                            "success": False,
                            "ign": entry.ign,
                            "error": str(e),
                            "error_code": "UNKNOWN_ERROR"
                        })
                        
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Queue processor error: {e}")
                
    def _get_cached(self, ign: str) -> Optional[Any]:
        """Get cached result if available and not expired."""
        if not self.cache_ttl:
            return None
            
        if ign in self._cache:
            result, timestamp = self._cache[ign]
            if time.time() - timestamp < self.cache_ttl:
                if hasattr(result, 'dict'):
                    data = result.dict()
                else:
                    data = result
                if isinstance(data, dict):
                    data['cached'] = True
                    data['cache_age'] = int(time.time() - timestamp)
                return data
            else:
                del self._cache[ign]
        return None
        
    def cleanup(self):
        """Cleanup on disconnect."""
        self._cache.clear()
        self._active_request = None
        
    def get_metrics(self) -> Dict[str, Any]:
        """Get current metrics."""
        return {
            "total_requests": self._metrics.total_requests,
            "successful_requests": self._metrics.successful_requests,
            "failed_requests": self._metrics.failed_requests,
            "cache_hits": self._metrics.cache_hits,
            "cache_misses": self._metrics.cache_misses,
            "avg_latency_ms": round(self._metrics.avg_latency_ms, 2),
            "success_rate": round(self._metrics.success_rate, 1)
        }
        
    async def stop(self):
        """Stop the queue processor."""
        self._running = False
