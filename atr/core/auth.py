"""API authentication utilities"""
from fastapi import Security, HTTPException, status
from fastapi.security import APIKeyHeader
from typing import Optional
import hashlib
import hmac

from atr.core.config import settings
from atr.core.cache import get_cache


api_key_header = APIKeyHeader(name=settings.api_key_header, auto_error=False)
cache = get_cache()


def verify_api_key(api_key: Optional[str] = Security(api_key_header)) -> str:
    """
    Verify API key from header.
    
    For MVP, we use a simple approach:
    - API keys are stored as hashed values in cache/database
    - In production, this would use a proper key management system
    
    For now, if API key authentication is disabled, allow all requests.
    """
    if not settings.api_key_enabled:
        return "anonymous"  # Allow all requests when auth is disabled
    
    if not api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="API key required",
            headers={"WWW-Authenticate": "ApiKey"},
        )
    
    # Check if API key is valid (stored in cache/database)
    # For MVP, we'll use a simple in-memory check
    # In production, this would check against a database of valid keys
    
    # Hash the provided key for comparison
    key_hash = hashlib.sha256(api_key.encode()).hexdigest()
    
    # Check cache for valid key hash
    # For MVP, we accept a simple validation
    # In production, implement proper key management
    valid_key = cache.get(f"api_key:{key_hash}")
    
    if not valid_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key",
            headers={"WWW-Authenticate": "ApiKey"},
        )
    
    return valid_key.get("owner", "authenticated")


def register_api_key(owner: str, api_key: str) -> bool:
    """Register an API key (for admin use)"""
    if not settings.api_key_enabled:
        return False
    
    key_hash = hashlib.sha256(api_key.encode()).hexdigest()
    return cache.set(
        f"api_key:{key_hash}",
        {"owner": owner, "created_at": "now"},
        ttl=None  # Keys don't expire (can be changed)
    )
