"""DNS TXT challenge validation for domain ownership"""
import dns.resolver
from typing import Optional
import time

from atr.core.config import settings
from atr.dns.providers import get_dns_provider


def generate_challenge_token(agent_name: str) -> str:
    """Generate a challenge token for DNS TXT validation"""
    import hashlib
    import secrets
    
    # Generate random token
    token = secrets.token_urlsafe(32)
    
    # Create challenge string
    challenge = f"atr-challenge={token}"
    return challenge


def validate_dns_challenge(agent_name: str, challenge_token: str, timeout: int = 300) -> bool:
    """
    Validate domain ownership via DNS TXT challenge.
    
    The challenge token should be present in a DNS TXT record:
    _atr-challenge.{agent_name} TXT "{challenge_token}"
    
    Args:
        agent_name: The agent name to validate
        challenge_token: The challenge token to look for
        timeout: Maximum time to wait for DNS propagation (seconds)
    
    Returns:
        True if challenge token is found in DNS, False otherwise
    """
    if not settings.domain_validation_enabled:
        return True  # Skip validation if disabled
    
    # Construct challenge record name
    challenge_name = f"_atr-challenge.{agent_name}"
    
    # Try to resolve DNS TXT record
    max_attempts = 10
    attempt = 0
    
    while attempt < max_attempts:
        try:
            # Query DNS TXT records
            answers = dns.resolver.resolve(challenge_name, 'TXT')
            
            for answer in answers:
                # TXT records come as lists of bytes
                txt_value = b''.join(answer.strings).decode('utf-8')
                
                # Check if challenge token matches
                if challenge_token in txt_value or txt_value == challenge_token:
                    return True
            
            # If we get here, TXT record exists but doesn't match
            attempt += 1
            if attempt < max_attempts:
                time.sleep(timeout / max_attempts)
        
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout):
            # DNS record doesn't exist or query timed out
            attempt += 1
            if attempt < max_attempts:
                time.sleep(timeout / max_attempts)
        
        except Exception:
            # Other DNS errors
            return False
    
    return False


def create_dns_challenge(agent_name: str, challenge_token: str) -> bool:
    """Create DNS TXT challenge record (for testing/internal use)"""
    if not settings.domain_validation_enabled:
        return False
    
    challenge_name = f"_atr-challenge.{agent_name}"
    dns_provider = get_dns_provider()
    
    try:
        return dns_provider.create_txt_record(challenge_name, challenge_token, ttl=300)
    except Exception:
        return False


class DomainValidationResult:
    """Result of domain validation"""
    def __init__(self, valid: bool, method: str, details: Optional[str] = None):
        self.valid = valid
        self.method = method
        self.details = details


def validate_domain_ownership_multi(agent_name: str, challenge_token: Optional[str] = None) -> DomainValidationResult:
    """
    Validate domain ownership using multiple methods.
    
    Methods tried (in order):
    1. DNS TXT challenge (if challenge_token provided)
    2. WHOIS validation (basic)
    
    Returns DomainValidationResult with validation status
    """
    if not settings.domain_validation_enabled:
        return DomainValidationResult(valid=True, method="disabled", details="Domain validation disabled")
    
    # Try DNS challenge first (most reliable)
    if challenge_token:
        if validate_dns_challenge(agent_name, challenge_token):
            return DomainValidationResult(valid=True, method="dns_challenge", details="DNS TXT challenge validated")
    
    # Fall back to WHOIS validation (basic)
    from atr.validation.whois import validate_domain_ownership
    if validate_domain_ownership(agent_name):
        return DomainValidationResult(valid=True, method="whois", details="Domain registered (WHOIS)")
    
    return DomainValidationResult(valid=False, method="none", details="Domain validation failed")
