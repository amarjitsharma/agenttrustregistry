"""Rate limiting utilities"""
from fastapi import Request, HTTPException, status
from slowapi import Limiter
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from typing import Optional, Callable
from functools import wraps

from atr.core.config import settings
from atr.core.cache import get_cache


def _rate_limit_exceeded_handler(request: Request, exc: RateLimitExceeded):
    """Handle rate limit exceeded exceptions"""
    response = HTTPException(
        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
        detail=f"Rate limit exceeded: {exc.detail}"
    )
    return response.response(request)


# Initialize limiter with Redis backend if available and enabled
if settings.rate_limit_enabled and settings.redis_enabled:
    try:
        limiter = Limiter(key_func=get_remote_address, storage_uri=settings.redis_url)
    except Exception:
        # Fallback to in-memory storage if Redis is not available
        limiter = Limiter(key_func=get_remote_address)
else:
    # Use in-memory storage if rate limiting is disabled or Redis unavailable
    limiter = Limiter(key_func=get_remote_address)


def get_rate_limiter() -> Limiter:
    """Get rate limiter instance"""
    return limiter


# v0.4: Advanced rate limiting per domain
def get_domain_from_agent_name(agent_name: str) -> Optional[str]:
    """Extract domain from agent name"""
    parts = agent_name.split('.')
    if len(parts) >= 2:
        return '.'.join(parts[-2:])  # Get last two parts as domain
    return None


def domain_rate_limit_key_func(request: Request) -> str:
    """Key function for per-domain rate limiting"""
    # Try to get domain from request body or path
    agent_name = None
    
    # Check path parameter
    if hasattr(request, 'path_params') and 'agent_name' in request.path_params:
        agent_name = request.path_params['agent_name']
    
    # Check JSON body (for POST requests)
    if not agent_name and request.method == 'POST':
        try:
            import json
            body = request.json()
            if isinstance(body, dict) and 'agent_name' in body:
                agent_name = body['agent_name']
        except Exception:
            pass
    
    if agent_name:
        domain = get_domain_from_agent_name(agent_name)
        if domain:
            return f"domain:{domain}"
    
    # Fallback to IP-based limiting
    return get_remote_address(request)


def create_domain_rate_limiter() -> Limiter:
    """Create rate limiter for per-domain limiting"""
    if settings.rate_limit_per_domain_enabled and settings.redis_enabled:
        try:
            return Limiter(
                key_func=domain_rate_limit_key_func,
                storage_uri=settings.redis_url
            )
        except Exception:
            return Limiter(key_func=domain_rate_limit_key_func)
    else:
        return Limiter(key_func=domain_rate_limit_key_func)


# Per-domain limiter instance
_domain_limiter: Optional[Limiter] = None


def get_domain_rate_limiter() -> Limiter:
    """Get per-domain rate limiter instance"""
    global _domain_limiter
    if _domain_limiter is None:
        _domain_limiter = create_domain_rate_limiter()
    return _domain_limiter
