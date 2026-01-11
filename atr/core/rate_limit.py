"""Rate limiting utilities"""
from fastapi import Request, HTTPException, status
from slowapi import Limiter
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

from atr.core.config import settings


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
