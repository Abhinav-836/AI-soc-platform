import redis
import json
from typing import Any, Optional

class CacheStorage:
    """Redis cache storage."""
    
    def __init__(self, host: str, port: int, db: int = 0):
        self.client = redis.Redis(host=host, port=port, db=db, decode_responses=True)
    
    def set(self, key: str, value: Any, ttl: Optional[int] = None):
        """Set cache value with optional TTL."""
        serialized = json.dumps(value)
        if ttl:
            self.client.setex(key, ttl, serialized)
        else:
            self.client.set(key, serialized)
    
    def get(self, key: str) -> Optional[Any]:
        """Get cache value."""
        value = self.client.get(key)
        return json.loads(value) if value else None
    
    def delete(self, key: str):
        """Delete cache key."""
        self.client.delete(key)
    
    def increment(self, key: str, amount: int = 1) -> int:
        """Increment counter."""
        return self.client.incrby(key, amount)
    
    def get_counter(self, key: str) -> int:
        """Get counter value."""
        value = self.client.get(key)
        return int(value) if value else 0
    
    def set_with_expiry(self, key: str, value: Any, seconds: int):
        """Set value with expiration."""
        self.set(key, value, ttl=seconds)