"""Performance Metrics and Monitoring (v0.4)

This module provides performance monitoring capabilities including:
- Request timing and latency tracking
- Database query performance
- Cache hit/miss rates
- API endpoint metrics
"""
from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta
from collections import defaultdict
from time import time
from functools import wraps
import json

from atr.core.cache import get_cache
from atr.core.config import settings


class PerformanceMetrics:
    """Performance metrics collector"""
    
    def __init__(self):
        self.cache = get_cache()
        self.metrics_prefix = "metrics:"
    
    def record_request(
        self,
        endpoint: str,
        method: str,
        duration_ms: float,
        status_code: int
    ):
        """Record API request metrics"""
        if not settings.performance_monitoring_enabled:
            return
        
        timestamp = int(time())
        minute_bucket = timestamp // 60
        
        # Record request count
        count_key = f"{self.metrics_prefix}requests:{endpoint}:{method}:{minute_bucket}"
        self.cache.increment(count_key, ttl=3600)
        
        # Record latency (p50, p95, p99)
        latency_key = f"{self.metrics_prefix}latency:{endpoint}:{method}:{minute_bucket}"
        # Store latency values (simplified - in production use proper percentile tracking)
        self.cache.set(f"{latency_key}:latest", duration_ms, ttl=3600)
        
        # Record status codes
        status_key = f"{self.metrics_prefix}status:{endpoint}:{method}:{status_code}:{minute_bucket}"
        self.cache.increment(status_key, ttl=3600)
    
    def record_database_query(
        self,
        query_type: str,
        duration_ms: float
    ):
        """Record database query performance"""
        if not settings.performance_monitoring_enabled:
            return
        
        timestamp = int(time())
        minute_bucket = timestamp // 60
        
        key = f"{self.metrics_prefix}db:{query_type}:{minute_bucket}"
        self.cache.set(f"{key}:latest", duration_ms, ttl=3600)
        self.cache.increment(f"{key}:count", ttl=3600)
    
    def record_cache_operation(
        self,
        operation: str,
        hit: bool
    ):
        """Record cache operation (hit/miss)"""
        if not settings.performance_monitoring_enabled:
            return
        
        timestamp = int(time())
        minute_bucket = timestamp // 60
        
        result = "hit" if hit else "miss"
        key = f"{self.metrics_prefix}cache:{operation}:{result}:{minute_bucket}"
        self.cache.increment(key, ttl=3600)
    
    def get_metrics_summary(
        self,
        time_window_minutes: int = 60
    ) -> Dict[str, Any]:
        """
        Get performance metrics summary.
        
        Args:
            time_window_minutes: Time window in minutes
            
        Returns:
            Dict with performance metrics
        """
        # This is a simplified implementation
        # In production, use proper time-series database or metrics service
        return {
            "time_window_minutes": time_window_minutes,
            "generated_at": datetime.utcnow().isoformat(),
            "note": "Performance metrics collection is enabled. Use APM tools for detailed metrics."
        }


# Global metrics instance
_metrics: Optional[PerformanceMetrics] = None


def get_metrics() -> PerformanceMetrics:
    """Get or create global metrics instance"""
    global _metrics
    if _metrics is None:
        _metrics = PerformanceMetrics()
    return _metrics


def track_performance(endpoint_name: Optional[str] = None):
    """Decorator to track endpoint performance"""
    def decorator(func):
        @wraps(func)
        async def async_wrapper(*args, **kwargs):
            start_time = time()
            try:
                result = await func(*args, **kwargs)
                status_code = 200
                return result
            except HTTPException as e:
                status_code = e.status_code
                raise
            finally:
                duration_ms = (time() - start_time) * 1000
                endpoint = endpoint_name or func.__name__
                get_metrics().record_request(
                    endpoint=endpoint,
                    method="GET",  # Could be extracted from request
                    duration_ms=duration_ms,
                    status_code=status_code
                )
        
        @wraps(func)
        def sync_wrapper(*args, **kwargs):
            from fastapi import HTTPException
            start_time = time()
            status_code = 200
            try:
                result = func(*args, **kwargs)
                status_code = 200
                return result
            except HTTPException as e:
                status_code = e.status_code
                raise
            finally:
                duration_ms = (time() - start_time) * 1000
                endpoint = endpoint_name or func.__name__
                get_metrics().record_request(
                    endpoint=endpoint,
                    method="GET",
                    duration_ms=duration_ms,
                    status_code=status_code
                )
        
        # Return appropriate wrapper based on function type
        import asyncio
        if asyncio.iscoroutinefunction(func):
            return async_wrapper
        else:
            return sync_wrapper
    
    return decorator
