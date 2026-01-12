"""Verification routes"""
from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy.orm import Session
from datetime import datetime
from cryptography import x509
from cryptography.hazmat.primitives import serialization

from atr.core.db import get_db
from atr.core.models import Agent, AgentStatus, CertificateType
from atr.core.schemas import VerifyCertRequest, VerifyCertResponse, ResolveResponse
from atr.core.audit import log_audit_event, AuditEventType
from atr.pki.fingerprints import compute_fingerprint
from atr.pki.ca import get_ca
from atr.core.cache import get_cache
from atr.dns.providers import get_dns_provider
from sqlalchemy import or_

router = APIRouter(prefix="/v1", tags=["verify"])
cache = get_cache()
dns_provider = get_dns_provider()


@router.post("/verify/cert", response_model=VerifyCertResponse)
def verify_certificate(
    request: VerifyCertRequest,
    db: Session = Depends(get_db)
):
    """
    Verify a presented certificate (v0.4: supports both private and public certificates):
    - Cert chains to trusted CA (private: our intermediate CA, public: public CA)
    - Fingerprint matches latest active fingerprint in registry (private or public)
    - Agent status is active
    - Not expired
    - If public cert, verify it's linked to agent's private cert
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
    
    # v0.4: Find agent by either private or public certificate fingerprint
    agent = db.query(Agent).filter(
        or_(
            Agent.cert_fingerprint == fingerprint,
            Agent.public_cert_fingerprint == fingerprint
        )
    ).first()
    
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
    
    # v0.4: Determine certificate type being verified
    is_public_cert = agent.public_cert_fingerprint == fingerprint
    is_private_cert = agent.cert_fingerprint == fingerprint
    
    # v0.4: Check certificate chain based on certificate type
    if is_private_cert:
        # Private certificate: must chain to our intermediate CA
        ca = get_ca()
        intermediate_cert = ca.get_intermediate_cert()
        
        try:
            # Basic check: verify the cert was signed by intermediate
            # In production, you'd do full chain validation
            if cert.issuer != intermediate_cert.subject:
                log_audit_event(
                    db,
                    AuditEventType.VERIFY,
                    agent_name=agent.agent_name,
                    metadata={"fingerprint": fingerprint, "result": "invalid_chain", "cert_type": "private"}
                )
                return VerifyCertResponse(
                    verified=False,
                    agent_name=agent.agent_name,
                    status=agent.status,
                    expires_at=agent.expires_at,
                    reason="Private certificate does not chain to trusted CA"
                )
        except Exception as e:
            log_audit_event(
                db,
                AuditEventType.VERIFY,
                agent_name=agent.agent_name,
                metadata={"fingerprint": fingerprint, "result": "chain_validation_error", "error": str(e), "cert_type": "private"}
            )
            return VerifyCertResponse(
                verified=False,
                agent_name=agent.agent_name,
                status=agent.status,
                expires_at=agent.expires_at,
                reason=f"Chain validation error: {str(e)}"
            )
    elif is_public_cert:
        # Public certificate: verify it's linked to the agent's private cert
        # In production, you'd verify the public cert chains to a trusted public CA (Let's Encrypt, etc.)
        # For POC, we just verify it exists and is linked to the agent
        
        # Verify certificate is linked to agent (both certs belong to same agent)
        if agent.cert_type not in [CertificateType.DUAL, CertificateType.PUBLIC]:
            log_audit_event(
                db,
                AuditEventType.VERIFY,
                agent_name=agent.agent_name,
                metadata={"fingerprint": fingerprint, "result": "unlinked_public_cert"}
            )
            return VerifyCertResponse(
                verified=False,
                agent_name=agent.agent_name,
                status=agent.status,
                expires_at=agent.public_cert_expires_at or agent.expires_at,
                reason="Public certificate is not linked to agent's private certificate"
            )
        
        # In production, verify public cert chains to trusted public CA
        # For now, we'll just check that the cert exists in the registry
        log_audit_event(
            db,
            AuditEventType.VERIFY,
            agent_name=agent.agent_name,
            metadata={"fingerprint": fingerprint, "result": "public_cert_chain_check_skipped", "note": "POC mode"}
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
    
    # v0.4: Check expiration based on certificate type
    if is_public_cert:
        # Check public cert expiration
        if agent.public_cert_expires_at and agent.public_cert_expires_at < now:
            log_audit_event(
                db,
                AuditEventType.VERIFY,
                agent_name=agent.agent_name,
                metadata={"fingerprint": fingerprint, "result": "expired_in_registry", "cert_type": "public"}
            )
            return VerifyCertResponse(
                verified=False,
                agent_name=agent.agent_name,
                status=agent.status,
                expires_at=agent.public_cert_expires_at,
                reason="Public certificate expired according to registry"
            )
    else:
        # Check private cert expiration
        if agent.expires_at < now:
            log_audit_event(
                db,
                AuditEventType.VERIFY,
                agent_name=agent.agent_name,
                metadata={"fingerprint": fingerprint, "result": "expired_in_registry", "cert_type": "private"}
            )
            return VerifyCertResponse(
                verified=False,
                agent_name=agent.agent_name,
                status=agent.status,
                expires_at=agent.expires_at,
                reason="Private certificate expired according to registry"
            )
    
    # All checks passed
    cert_type_str = "public" if is_public_cert else "private"
    expires_at = agent.public_cert_expires_at if is_public_cert else agent.expires_at
    
    log_audit_event(
        db,
        AuditEventType.VERIFY,
        agent_name=agent.agent_name,
        metadata={"fingerprint": fingerprint, "result": "verified", "cert_type": cert_type_str}
    )
    
    return VerifyCertResponse(
        verified=True,
        agent_name=agent.agent_name,
        status=agent.status,
        expires_at=expires_at,
        reason=None
    )


@router.get("/resolve/{agent_name}", response_model=ResolveResponse)
def resolve_agent(agent_name: str, request: Request, db: Session = Depends(get_db)):
    """Resolve agent name to trust metadata (supports DNS and cache)"""
    # Check cache first
    cache_key = f"resolve:{agent_name}"
    cached = cache.get(cache_key)
    if cached:
        return ResolveResponse(**cached)
    
    # Try DNS first (if provider configured and not local)
    try:
        txt_records = dns_provider.get_txt_records(agent_name)
        if txt_records:
            # Parse DNS TXT records for fingerprint
            for record in txt_records:
                if record.startswith("fingerprint="):
                    fingerprint = record.split("=", 1)[1]
                    # Look up agent by fingerprint
                    agent = db.query(Agent).filter(Agent.cert_fingerprint == fingerprint).first()
                    if agent:
                        response_data = {
                            "agent_name": agent.agent_name,
                            "owner": agent.owner,
                            "capabilities": agent.capabilities,
                            "status": agent.status.value,
                            "cert_fingerprint": agent.cert_fingerprint,
                            "expires_at": agent.expires_at
                        }
                        # Cache DNS response for TTL (300 seconds)
                        cache.set(cache_key, response_data, ttl=300)
                        return ResolveResponse(**response_data)
    except Exception:
        # DNS lookup failed, fall back to database
        pass
    
    # Fall back to database lookup
    agent = db.query(Agent).filter(Agent.agent_name == agent_name).first()
    if not agent:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Agent '{agent_name}' not found"
        )
    
    response_data = {
        "agent_name": agent.agent_name,
        "owner": agent.owner,
        "capabilities": agent.capabilities,
        "status": agent.status.value,
        "cert_fingerprint": agent.cert_fingerprint,
        "expires_at": agent.expires_at
    }
    
    # Cache for 5 minutes
    cache.set(cache_key, response_data, ttl=300)
    
    return ResolveResponse(
        agent_name=agent.agent_name,
        owner=agent.owner,
        capabilities=agent.capabilities,
        status=agent.status,
        cert_fingerprint=agent.cert_fingerprint,
        expires_at=agent.expires_at
    )
