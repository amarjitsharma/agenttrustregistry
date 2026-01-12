"""Redis caching utilities"""
import json
from typing import Optional, Any
from datetime import timedelta
import redis
from redis.exceptions import RedisError

from atr.core.config import settings


class Cache:
    """Redis cache wrapper"""
    
    def __init__(self):
        self._client: Optional[redis.Redis] = None
        self._enabled = settings.redis_enabled
    
    def _get_client(self) -> Optional[redis.Redis]:
        """Get Redis client (lazy initialization)"""
        if not self._enabled:
            return None
        
        if self._client is None:
            try:
                self._client = redis.from_url(
                    settings.redis_url,
                    decode_responses=True,
                    socket_connect_timeout=2,
                    socket_timeout=2
                )
                # Test connection
                self._client.ping()
            except (RedisError, ConnectionError, OSError):
                # Redis not available, disable caching
                self._enabled = False
                self._client = None
        
        return self._client
    
    def get(self, key: str) -> Optional[Any]:
        """Get value from cache"""
        client = self._get_client()
        if not client:
            return None
        
        try:
            value = client.get(key)
            if value:
                return json.loads(value)
        except (RedisError, json.JSONDecodeError):
            pass
        
        return None
    
    def set(self, key: str, value: Any, ttl: Optional[int] = None) -> bool:
        """Set value in cache with optional TTL (seconds)"""
        client = self._get_client()
        if not client:
            return False
        
        try:
            serialized = json.dumps(value, default=str)
            if ttl:
                client.setex(key, ttl, serialized)
            else:
                client.set(key, serialized)
            return True
        except (RedisError, TypeError):
            pass
        
        return False
    
    def delete(self, key: str) -> bool:
        """Delete key from cache"""
        client = self._get_client()
        if not client:
            return False
        
        try:
            client.delete(key)
            return True
        except RedisError:
            pass
        
        return False
    
    def delete_pattern(self, pattern: str) -> int:
        """Delete all keys matching pattern"""
        client = self._get_client()
        if not client:
            return 0
        
        try:
            keys = client.keys(pattern)
            if keys:
                return client.delete(*keys)
        except RedisError:
            pass
        
        return 0
    
    def increment(self, key: str, amount: int = 1, ttl: Optional[int] = None) -> int:
        """
        Increment a counter in cache (v0.4: for metrics).
        
        Args:
            key: Cache key
            amount: Amount to increment (default: 1)
            ttl: Optional TTL in seconds
            
        Returns:
            New value after increment
        """
        client = self._get_client()
        if not client:
            return 0
        
        try:
            value = client.incrby(key, amount)
            if ttl:
                client.expire(key, ttl)
            return value
        except RedisError:
            return 0


# Global cache instance
_cache_instance: Optional[Cache] = None


def get_cache() -> Cache:
    """Get or create global cache instance"""
    global _cache_instance
    if _cache_instance is None:
        _cache_instance = Cache()
    return _cache_instance
