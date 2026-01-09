"""Input validation utilities"""
import re
from typing import Optional


# DNS label pattern: lowercase letters, digits, hyphen, dot
# No leading/trailing dots, max 253 chars total
AGENT_NAME_PATTERN = re.compile(r'^[a-z0-9]([a-z0-9\-\.]{0,251}[a-z0-9])?$')
AGENT_NAME_MIN_LEN = 1
AGENT_NAME_MAX_LEN = 253


def validate_agent_name(agent_name: str) -> Optional[str]:
    """
    Validate agent name according to DNS-label rules.
    
    Rules:
    - Lowercase letters, digits, hyphen, dot only
    - No leading/trailing dots
    - Length 1-253 characters
    - Each label segment max 63 chars (not enforced here, but should be)
    
    Returns:
        None if valid, error message if invalid
    """
    if not agent_name:
        return "Agent name cannot be empty"
    
    if len(agent_name) < AGENT_NAME_MIN_LEN:
        return f"Agent name must be at least {AGENT_NAME_MIN_LEN} character(s)"
    
    if len(agent_name) > AGENT_NAME_MAX_LEN:
        return f"Agent name must be at most {AGENT_NAME_MAX_LEN} characters"
    
    if not AGENT_NAME_PATTERN.match(agent_name):
        return (
            "Agent name must contain only lowercase letters, digits, hyphens, and dots. "
            "Cannot start or end with a dot."
        )
    
    # Check individual label lengths (max 63 chars per label)
    labels = agent_name.split('.')
    for label in labels:
        if len(label) > 63:
            return f"Label '{label}' exceeds maximum length of 63 characters"
        if len(label) == 0:
            return "Agent name cannot contain consecutive dots"
    
    return None
