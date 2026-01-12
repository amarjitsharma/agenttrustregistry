"""Domain Connect API routes (v0.4)"""
from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.orm import Session
from typing import Optional, Dict, Any

from atr.core.db import get_db
from atr.core.config import settings
from atr.validation.domain_connect import (
    DomainConnectClient,
    get_domain_connect_client
)

router = APIRouter(prefix="/v1", tags=["domain-connect"])


@router.get("/domain-connect/authorize")
def get_authorization_url(
    domain: str = Query(..., description="Domain name"),
    redirect_uri: str = Query(..., description="OAuth redirect URI"),
    state: Optional[str] = Query(None, description="OAuth state parameter")
):
    """
    Get Domain Connect OAuth authorization URL.
    
    Args:
        domain: Domain name to authorize
        redirect_uri: Redirect URI after authorization
        state: Optional state parameter for CSRF protection
        
    Returns:
        Dict with authorization URL
    """
    if not settings.domain_connect_enabled:
        raise HTTPException(
            status_code=status.HTTP_501_NOT_IMPLEMENTED,
            detail="Domain Connect integration is not enabled in configuration."
        )
    
    try:
        client = get_domain_connect_client()
        auth_url = client.get_oauth_authorization_url(domain, redirect_uri, state)
        
        return {
            "authorization_url": auth_url,
            "domain": domain,
            "redirect_uri": redirect_uri,
            "state": state
        }
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to generate authorization URL: {str(e)}"
        )


@router.post("/domain-connect/callback")
def handle_oauth_callback(
    code: str = Query(..., description="OAuth authorization code"),
    state: Optional[str] = Query(None, description="OAuth state parameter"),
    redirect_uri: str = Query(..., description="Redirect URI")
):
    """
    Handle OAuth callback from Domain Connect provider.
    
    Args:
        code: Authorization code
        state: State parameter (for CSRF protection)
        redirect_uri: Redirect URI used in authorization
        
    Returns:
        Dict with access token information
    """
    if not settings.domain_connect_enabled:
        raise HTTPException(
            status_code=status.HTTP_501_NOT_IMPLEMENTED,
            detail="Domain Connect integration is not enabled in configuration."
        )
    
    try:
        client = get_domain_connect_client()
        token_info = client.exchange_authorization_code(code, redirect_uri)
        
        return {
            "success": True,
            "token_info": token_info,
            "state": state
        }
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to exchange authorization code: {str(e)}"
        )


@router.post("/domain-connect/verify")
def verify_domain_ownership(
    domain: str = Query(..., description="Domain name"),
    access_token: Optional[str] = Query(None, description="OAuth access token")
):
    """
    Verify domain ownership via Domain Connect API.
    
    Args:
        domain: Domain name to verify
        access_token: Optional OAuth access token
        
    Returns:
        Dict with verification result
    """
    if not settings.domain_connect_enabled:
        raise HTTPException(
            status_code=status.HTTP_501_NOT_IMPLEMENTED,
            detail="Domain Connect integration is not enabled in configuration."
        )
    
    try:
        client = get_domain_connect_client()
        result = client.verify_domain_ownership(domain, access_token)
        
        return result
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to verify domain ownership: {str(e)}"
        )


@router.post("/domain-connect/dns/create")
def create_dns_record_via_domain_connect(
    domain: str = Query(..., description="Domain name"),
    record_type: str = Query(..., description="DNS record type (TXT, A, etc.)"),
    name: str = Query(..., description="Record name (subdomain)"),
    value: str = Query(..., description="Record value"),
    ttl: int = Query(300, description="TTL in seconds"),
    access_token: Optional[str] = Query(None, description="OAuth access token")
):
    """
    Create DNS record via Domain Connect API.
    
    Args:
        domain: Domain name
        record_type: DNS record type
        name: Record name
        value: Record value
        ttl: TTL in seconds
        access_token: Optional OAuth access token
        
    Returns:
        Dict with operation result
    """
    if not settings.domain_connect_enabled:
        raise HTTPException(
            status_code=status.HTTP_501_NOT_IMPLEMENTED,
            detail="Domain Connect integration is not enabled in configuration."
        )
    
    try:
        client = get_domain_connect_client()
        result = client.create_dns_record(domain, record_type, name, value, ttl, access_token)
        
        return result
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to create DNS record: {str(e)}"
        )
