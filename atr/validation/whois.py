"""WHOIS integration for domain validation"""
import socket
import re
from typing import Optional, Dict, Any
from datetime import datetime

from atr.core.config import settings


def query_whois(domain: str) -> Optional[Dict[str, Any]]:
    """
    Query WHOIS for domain information.
    
    Note: This is a simplified implementation for POC.
    In production, use a proper WHOIS library like python-whois.
    """
    if not settings.domain_validation_enabled:
        return None
    
    # Extract base domain (remove subdomain)
    parts = domain.split('.')
    if len(parts) < 2:
        return None
    
    base_domain = '.'.join(parts[-2:])  # Get last two parts (e.g., example.com)
    
    try:
        # Simple WHOIS query via socket (for demo)
        # In production, use proper WHOIS library
        whois_server = "whois.iana.org"
        
        # This is a simplified implementation
        # Real implementation would:
        # 1. Query appropriate WHOIS server for TLD
        # 2. Parse WHOIS response
        # 3. Extract registrar, creation date, expiration date, etc.
        
        # For POC, return mock data
        return {
            "domain": base_domain,
            "status": "registered",
            "created": None,
            "expires": None,
            "registrar": None
        }
    except Exception:
        return None


def validate_domain_ownership(domain: str) -> bool:
    """
    Validate domain ownership via WHOIS.
    
    This is a placeholder for actual WHOIS validation.
    In production, you would:
    1. Query WHOIS for domain
    2. Check domain status
    3. Verify domain exists and is active
    """
    if not settings.domain_validation_enabled:
        return True  # Skip validation if disabled
    
    whois_data = query_whois(domain)
    if not whois_data:
        return False
    
    return whois_data.get("status") == "registered"


def extract_base_domain(agent_name: str) -> Optional[str]:
    """Extract base domain from agent name (e.g., agent.example.com -> example.com)"""
    parts = agent_name.split('.')
    if len(parts) < 2:
        return None
    return '.'.join(parts[-2:])
