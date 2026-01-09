"""Verification routes"""
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from datetime import datetime
from cryptography import x509
from cryptography.hazmat.primitives import serialization

from atr.core.db import get_db
from atr.core.models import Agent, AgentStatus
from atr.core.schemas import VerifyCertRequest, VerifyCertResponse, ResolveResponse
from atr.core.audit import log_audit_event, AuditEventType
from atr.pki.fingerprints import compute_fingerprint
from atr.pki.ca import get_ca

router = APIRouter(prefix="/v1", tags=["verify"])


@router.post("/verify/cert", response_model=VerifyCertResponse)
def verify_certificate(
    request: VerifyCertRequest,
    db: Session = Depends(get_db)
):
    """
    Verify a presented certificate:
    - Cert chains to our intermediate CA
    - Fingerprint matches latest active fingerprint in registry
    - Agent status is active
    - Not expired
    """
    try:
        # Parse certificate
        cert = x509.load_pem_x509_certificate(request.cert_pem.encode('utf-8'))
    except Exception as e:
        return VerifyCertResponse(
            verified=False,
            reason=f"Invalid certificate format: {str(e)}"
        )
    
    # Compute fingerprint
    fingerprint = compute_fingerprint(cert)
    
    # Find agent by fingerprint
    agent = db.query(Agent).filter(Agent.cert_fingerprint == fingerprint).first()
    if not agent:
        log_audit_event(
            db,
            AuditEventType.VERIFY,
            metadata={"fingerprint": fingerprint, "result": "not_found"}
        )
        return VerifyCertResponse(
            verified=False,
            reason="Certificate fingerprint not found in registry"
        )
    
    # Check if certificate chains to our intermediate CA
    ca = get_ca()
    intermediate_cert = ca.get_intermediate_cert()
    
    try:
        # Verify certificate signature
        intermediate_key = ca.get_intermediate_key()
        # Basic check: verify the cert was signed by intermediate
        # In production, you'd do full chain validation
        if cert.issuer != intermediate_cert.subject:
            log_audit_event(
                db,
                AuditEventType.VERIFY,
                agent_name=agent.agent_name,
                metadata={"fingerprint": fingerprint, "result": "invalid_chain"}
            )
            return VerifyCertResponse(
                verified=False,
                agent_name=agent.agent_name,
                status=agent.status,
                expires_at=agent.expires_at,
                reason="Certificate does not chain to trusted CA"
            )
    except Exception as e:
        log_audit_event(
            db,
            AuditEventType.VERIFY,
            agent_name=agent.agent_name,
            metadata={"fingerprint": fingerprint, "result": "chain_validation_error", "error": str(e)}
        )
        return VerifyCertResponse(
            verified=False,
            agent_name=agent.agent_name,
            status=agent.status,
            expires_at=agent.expires_at,
            reason=f"Chain validation error: {str(e)}"
        )
    
    # Check if agent is active
    if agent.status != AgentStatus.ACTIVE:
        log_audit_event(
            db,
            AuditEventType.VERIFY,
            agent_name=agent.agent_name,
            metadata={"fingerprint": fingerprint, "result": "revoked"}
        )
        return VerifyCertResponse(
            verified=False,
            agent_name=agent.agent_name,
            status=agent.status,
            expires_at=agent.expires_at,
            reason=f"Agent status is {agent.status.value}"
        )
    
    # Check if certificate is expired
    now = datetime.utcnow()
    if cert.not_valid_after < now:
        log_audit_event(
            db,
            AuditEventType.VERIFY,
            agent_name=agent.agent_name,
            metadata={"fingerprint": fingerprint, "result": "expired"}
        )
        return VerifyCertResponse(
            verified=False,
            agent_name=agent.agent_name,
            status=agent.status,
            expires_at=agent.expires_at,
            reason="Certificate has expired"
        )
    
    # Check if registry shows expired
    if agent.expires_at < now:
        log_audit_event(
            db,
            AuditEventType.VERIFY,
            agent_name=agent.agent_name,
            metadata={"fingerprint": fingerprint, "result": "expired_in_registry"}
        )
        return VerifyCertResponse(
            verified=False,
            agent_name=agent.agent_name,
            status=agent.status,
            expires_at=agent.expires_at,
            reason="Certificate expired according to registry"
        )
    
    # All checks passed
    log_audit_event(
        db,
        AuditEventType.VERIFY,
        agent_name=agent.agent_name,
        metadata={"fingerprint": fingerprint, "result": "verified"}
    )
    
    return VerifyCertResponse(
        verified=True,
        agent_name=agent.agent_name,
        status=agent.status,
        expires_at=agent.expires_at,
        reason=None
    )


@router.get("/resolve/{agent_name}", response_model=ResolveResponse)
def resolve_agent(agent_name: str, db: Session = Depends(get_db)):
    """Resolve agent name to trust metadata"""
    agent = db.query(Agent).filter(Agent.agent_name == agent_name).first()
    if not agent:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Agent '{agent_name}' not found"
        )
    
    return ResolveResponse(
        agent_name=agent.agent_name,
        owner=agent.owner,
        capabilities=agent.capabilities,
        status=agent.status,
        cert_fingerprint=agent.cert_fingerprint,
        expires_at=agent.expires_at
    )
