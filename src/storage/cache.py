"""Small thread-safe TTL cache (used for threat-intel lookups)."""
import threading
import time
from typing import Any, Dict, Optional, Tuple


class TTLCache:
    def __init__(self, ttl_seconds: float = 3600, max_items: int = 10000):
        self.ttl = ttl_seconds
        self.max_items = max_items
        self._data: Dict[str, Tuple[float, Any]] = {}
        self._lock = threading.Lock()

    def get(self, key: str) -> Optional[Any]:
        with self._lock:
            item = self._data.get(key)
            if not item:
                return None
            expires, value = item
            if expires < time.time():
                del self._data[key]
                return None
            return value

    def set(self, key: str, value: Any, ttl: Optional[float] = None):
        with self._lock:
            if len(self._data) >= self.max_items:
                # drop the entry closest to expiry
                oldest = min(self._data, key=lambda k: self._data[k][0])
                del self._data[oldest]
            self._data[key] = (time.time() + (ttl or self.ttl), value)

    def clear(self):
        with self._lock:
            self._data.clear()

    def __len__(self) -> int:
        return len(self._data)


# old name
CacheStorage = TTLCache
