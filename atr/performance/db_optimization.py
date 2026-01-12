"""Database Query Optimization (v0.4)

This module provides database query optimization utilities including:
- Query result caching
- Query performance tracking
- Index recommendations
- Connection pool optimization
"""
from typing import Optional, Dict, Any, List
from functools import wraps
from time import time
from sqlalchemy.orm import Session
from sqlalchemy import event
from sqlalchemy.engine import Engine

from atr.core.cache import get_cache
from atr.core.config import settings
from atr.performance.metrics import get_metrics


class QueryOptimizer:
    """Database query optimizer"""
    
    def __init__(self):
        self.cache = get_cache()
        self.metrics = get_metrics()
        self.query_cache_enabled = getattr(settings, 'query_cache_enabled', False)
    
    def cache_query_result(
        self,
        cache_key: str,
        result: Any,
        ttl: int = 300
    ):
        """Cache a query result"""
        if self.query_cache_enabled:
            self.cache.set(cache_key, result, ttl=ttl)
    
    def get_cached_query_result(self, cache_key: str) -> Optional[Any]:
        """Get cached query result"""
        if self.query_cache_enabled:
            return self.cache.get(cache_key)
        return None
    
    def track_query_performance(
        self,
        query_type: str,
        duration_ms: float
    ):
        """Track query performance"""
        self.metrics.record_database_query(query_type, duration_ms)


# Global query optimizer instance
_query_optimizer: Optional[QueryOptimizer] = None


def get_query_optimizer() -> QueryOptimizer:
    """Get or create global query optimizer instance"""
    global _query_optimizer
    if _query_optimizer is None:
        _query_optimizer = QueryOptimizer()
    return _query_optimizer


def optimize_connection_pool(engine: Engine):
    """
    Optimize database connection pool settings.
    
    Args:
        engine: SQLAlchemy engine
    """
    # Set connection pool settings for better performance
    if hasattr(engine.pool, 'size'):
        # Adjust pool size based on configuration
        pool_size = getattr(settings, 'db_pool_size', 5)
        max_overflow = getattr(settings, 'db_pool_max_overflow', 10)
        
        engine.pool.size = pool_size
        engine.pool.max_overflow = max_overflow
        engine.pool.pool_timeout = 30
        engine.pool.recycle = 3600  # Recycle connections after 1 hour


def setup_query_logging(engine: Engine):
    """
    Setup query performance logging (for development/debugging).
    
    Args:
        engine: SQLAlchemy engine
    """
    if not getattr(settings, 'db_query_logging_enabled', False):
        return
    
    @event.listens_for(engine, "before_cursor_execute")
    def receive_before_cursor_execute(conn, cursor, statement, parameters, context, executemany):
        conn.info.setdefault('query_start_time', []).append(time())
    
    @event.listens_for(engine, "after_cursor_execute")
    def receive_after_cursor_execute(conn, cursor, statement, parameters, context, executemany):
        total = time() - conn.info['query_start_time'].pop(-1)
        
        # Log slow queries (>100ms)
        if total > 0.1:
            optimizer = get_query_optimizer()
            optimizer.track_query_performance("slow_query", total * 1000)
