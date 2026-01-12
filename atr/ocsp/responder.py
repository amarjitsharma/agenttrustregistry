"""OCSP responder implementation"""
from datetime import datetime, timedelta
from typing import Optional, Dict, Any
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
# OCSP imports - simplified for POC
# Full OCSP implementation would require proper request/response handling
from sqlalchemy.orm import Session

from atr.core.db import get_db
from atr.core.models import Agent, AgentStatus
from atr.pki.ca import get_ca


def get_certificate_status(cert: x509.Certificate, db: Session) -> Dict[str, Any]:
    """
    Get certificate status for OCSP.
    
    Returns:
        dict with keys:
        - status: 'good', 'revoked', or 'unknown'
        - revocation_time: Optional[datetime] if revoked
        - revocation_reason: Optional[str] if revoked
    """
    # Find agent by certificate fingerprint
    from atr.pki.fingerprints import compute_fingerprint
    
    fingerprint = compute_fingerprint(cert)
    agent = db.query(Agent).filter(Agent.cert_fingerprint == fingerprint).first()
    
    if not agent:
        return {
            "status": "unknown",
            "revocation_time": None,
            "revocation_reason": None
        }
    
    # Check if revoked
    if agent.status == AgentStatus.REVOKED:
        # Try to get revocation time from audit events
        from atr.core.models import AuditEvent, AuditEventType
        revoke_event = db.query(AuditEvent).filter(
            AuditEvent.agent_name == agent.agent_name,
            AuditEvent.event_type == AuditEventType.REVOKE
        ).order_by(AuditEvent.timestamp.desc()).first()
        
        revocation_time = revoke_event.timestamp if revoke_event else agent.updated_at
        
        return {
            "status": "revoked",
            "revocation_time": revocation_time,
            "revocation_reason": "unspecified"  # Could be enhanced with reason from audit
        }
    
    # Check if expired
    now = datetime.utcnow()
    if agent.expires_at < now or cert.not_valid_after.replace(tzinfo=None) < now:
        return {
            "status": "good",  # OCSP doesn't handle expired - that's checked elsewhere
            "revocation_time": None,
            "revocation_reason": None
        }
    
    # Certificate is good (active and not revoked)
    return {
        "status": "good",
        "revocation_time": None,
        "revocation_reason": None
    }


def generate_ocsp_response_bytes(
    request_bytes: bytes,
    db: Session
) -> Optional[bytes]:
    """
    Generate OCSP response bytes for a certificate status request.
    
    Note: This is a simplified implementation for POC.
    In production, you'd want:
    - Proper request parsing (DER-encoded OCSP request)
    - Response signing with OCSP responder certificate
    - Response caching
    - Nonce handling
    - Proper DER-encoded response generation
    
    For now, this is a placeholder that returns None.
    Full OCSP implementation would require proper cryptography.x509.ocsp usage.
    """
    # Placeholder for full OCSP implementation
    # In production, this would:
    # 1. Parse OCSP request (DER format)
    # 2. Extract serial number from request
    # 3. Query certificate status from database
    # 4. Build and sign OCSP response
    # 5. Return DER-encoded response
    
    return None


def check_certificate_status_ocsp(
    cert: x509.Certificate,
    db: Session
) -> Dict[str, Any]:
    """
    Check certificate status using OCSP logic (internal use).
    
    This function provides the logic for checking certificate status
    that would be used by an OCSP responder, but can be called directly
    for internal verification.
    
    Returns:
        dict with certificate status information
    """
    return get_certificate_status(cert, db)


class OCSPResponder:
    """
    OCSP responder service.
    
    In production, this would:
    - Handle HTTP POST requests with OCSP requests
    - Generate and sign OCSP responses
    - Cache responses for performance
    - Handle nonces for replay attack prevention
    """
    
    def __init__(self, db: Session):
        self.db = db
        self.ca = get_ca()
    
    def process_request(self, ocsp_request_bytes: bytes) -> Optional[bytes]:
        """
        Process OCSP request and return OCSP response.
        
        Args:
            ocsp_request_bytes: DER-encoded OCSP request
            
        Returns:
            DER-encoded OCSP response, or None if error
        """
        try:
            # For POC, use simplified response generation
            # Full OCSP implementation would parse and handle requests properly
            return generate_ocsp_response_bytes(ocsp_request_bytes, self.db)
        except Exception:
            return None
    
    def get_certificate_status_by_serial(
        self,
        serial_number: str,
        issuer_name: x509.Name
    ) -> Dict[str, Any]:
        """
        Get certificate status by serial number and issuer.
        
        This is a helper method for building OCSP responses.
        """
        # Find certificate by serial number
        agent = self.db.query(Agent).filter(
            Agent.cert_serial_number == str(serial_number)
        ).first()
        
        if not agent:
            return {
                "status": "unknown",
                "revocation_time": None,
                "revocation_reason": None
            }
        
        # Check if revoked
        if agent.status == AgentStatus.REVOKED:
            # Get revocation time from audit events
            from atr.core.models import AuditEvent, AuditEventType
            revoke_event = self.db.query(AuditEvent).filter(
                AuditEvent.agent_name == agent.agent_name,
                AuditEvent.event_type == AuditEventType.REVOKE
            ).order_by(AuditEvent.timestamp.desc()).first()
            
            revocation_time = revoke_event.timestamp if revoke_event else agent.updated_at
            
            return {
                "status": "revoked",
                "revocation_time": revocation_time,
                "revocation_reason": "unspecified"
            }
        
        # Certificate is good (active and not revoked)
        return {
            "status": "good",
            "revocation_time": None,
            "revocation_reason": None
        }
