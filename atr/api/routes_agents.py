"""Agent lifecycle routes"""
from fastapi import APIRouter, Depends, HTTPException, status, Query, Request
from sqlalchemy.orm import Session
from sqlalchemy import or_
from datetime import datetime, timedelta
from typing import List, Optional
from cryptography.hazmat.primitives import serialization
from slowapi import Limiter

from atr.core.db import get_db
from atr.core.models import Agent, AgentStatus
from atr.core.schemas import (
    AgentRegisterRequest,
    AgentResponse,
    AgentRotateResponse,
    AgentRevokeResponse,
    AgentListResponse,
    AgentCertResponse,
)
from atr.core.validators import validate_agent_name
from atr.core.audit import log_audit_event, AuditEventType
from atr.pki.issue import issue_agent_certificate
from atr.pki.public_cert import issue_public_certificate
from atr.pki.fingerprints import compute_fingerprint
from atr.core.config import settings
from atr.core.cache import get_cache
from atr.core.models import CertificateType
from atr.core.rate_limit import get_rate_limiter
from atr.dns.providers import get_dns_provider

router = APIRouter(prefix="/v1/agents", tags=["agents"])
limiter = get_rate_limiter()
cache = get_cache()
dns_provider = get_dns_provider()


@router.get("", response_model=AgentListResponse)
def list_agents(
    db: Session = Depends(get_db),
    limit: int = Query(default=100, ge=1, le=1000, description="Maximum number of results"),
    offset: int = Query(default=0, ge=0, description="Pagination offset"),
    owner: Optional[str] = Query(default=None, description="Filter by owner"),
    status: Optional[AgentStatus] = Query(default=None, description="Filter by status"),
    capability: Optional[str] = Query(default=None, description="Filter by capability"),
):
    """List all agents with optional filtering and pagination"""
    query = db.query(Agent)
    
    # Apply filters
    if owner:
        query = query.filter(Agent.owner == owner)
    
    if status:
        query = query.filter(Agent.status == status)
    
    if capability:
        # Filter agents that have the specified capability
        query = query.filter(Agent.capabilities.contains([capability]))
    
    # Get total count before pagination
    total = query.count()
    
    # Apply pagination
    agents = query.order_by(Agent.created_at.desc()).offset(offset).limit(limit).all()
    
    # Convert to response format
    agent_list = [
        AgentResponse(
            agent_name=agent.agent_name,
            owner=agent.owner,
            capabilities=agent.capabilities,
            status=agent.status,
            cert_fingerprint=agent.cert_fingerprint,
            cert_serial_number=agent.cert_serial_number,  # v0.4: For OCSP
            cert_type=agent.cert_type,  # v0.4: Certificate type
            issued_at=agent.issued_at,
            expires_at=agent.expires_at,
            # v0.4: Public certificate fields
            public_cert_fingerprint=agent.public_cert_fingerprint,
            public_cert_serial_number=agent.public_cert_serial_number,
            public_cert_issued_at=agent.public_cert_issued_at,
            public_cert_expires_at=agent.public_cert_expires_at,
            public_cert_issuer=agent.public_cert_issuer,
            created_at=agent.created_at,
            updated_at=agent.updated_at
        )
        for agent in agents
    ]
    
    return AgentListResponse(
        agents=agent_list,
        total=total,
        limit=limit,
        offset=offset
    )


@router.post("", response_model=AgentResponse, status_code=status.HTTP_201_CREATED)
def register_agent(
    request: AgentRegisterRequest,
    db: Session = Depends(get_db)
):
    """Register a new agent and issue certificate"""
    # Validate agent name
    validation_error = validate_agent_name(request.agent_name)
    if validation_error:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=validation_error
        )
    
    # Domain validation (v0.3 feature - optional)
    if settings.domain_validation_enabled:
        try:
            from atr.validation.dns_challenge import validate_domain_ownership_multi
            validation_result = validate_domain_ownership_multi(request.agent_name)
            if not validation_result.valid:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Domain validation failed: {validation_result.details}"
                )
        except ImportError:
            # Domain validation module not available, skip
            pass
        except HTTPException:
            raise
        except Exception as e:
            # Domain validation errors shouldn't block registration in POC
            # In production, you might want to be stricter
            pass
    
    # Check if agent already exists
    existing = db.query(Agent).filter(Agent.agent_name == request.agent_name).first()
    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Agent '{request.agent_name}' already exists"
        )
    
    # Issue private certificate (always)
    try:
        private_key, cert, fingerprint = issue_agent_certificate(request.agent_name)
        cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode('utf-8')
        cert_serial_number = str(cert.serial_number)  # v0.4: Store serial for OCSP
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to issue private certificate: {str(e)}"
        )
    
    # v0.4: Issue public certificate if requested
    public_cert_pem = None
    public_cert_fingerprint = None
    public_cert_serial_number = None
    public_cert_issued_at = None
    public_cert_expires_at = None
    public_cert_issuer = None
    cert_type = CertificateType.PRIVATE
    
    if request.request_public_cert:
        if not settings.acme_enabled:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Public certificate issuance is not enabled. Set ACME_ENABLED=true in configuration."
            )
        
        try:
            public_key, public_cert, public_fingerprint = issue_public_certificate(request.agent_name)
            public_cert_pem = public_cert.public_bytes(serialization.Encoding.PEM).decode('utf-8')
            public_cert_serial_number = str(public_cert.serial_number)
            public_cert_issued_at = datetime.utcnow()
            public_cert_expires_at = public_cert.not_valid_after.replace(tzinfo=None)
            public_cert_fingerprint = public_fingerprint
            public_cert_issuer = "Let's Encrypt"  # In production, get from cert issuer
            cert_type = CertificateType.DUAL
        except Exception as e:
            # If public cert issuance fails, continue with private cert only
            # In production, you might want to fail or retry
            pass
    
    # Create agent record
    now = datetime.utcnow()
    agent = Agent(
        agent_name=request.agent_name,
        owner=request.owner,
        capabilities=request.capabilities,
        status=AgentStatus.ACTIVE,
        cert_fingerprint=fingerprint,
        cert_serial_number=cert_serial_number,  # v0.4: For OCSP
        cert_pem=cert_pem,
        cert_type=cert_type,  # v0.4: Certificate type
        issued_at=now,
        expires_at=now + timedelta(days=settings.cert_validity_days),
        # v0.4: Public certificate fields
        public_cert_fingerprint=public_cert_fingerprint,
        public_cert_pem=public_cert_pem,
        public_cert_serial_number=public_cert_serial_number,
        public_cert_issued_at=public_cert_issued_at,
        public_cert_expires_at=public_cert_expires_at,
        public_cert_issuer=public_cert_issuer,
        created_at=now,
        updated_at=now
    )
    
    db.add(agent)
    db.commit()
    db.refresh(agent)
    
    # Create DNS TXT record (if DNS provider is configured)
    try:
        dns_value = f"fingerprint={fingerprint}"
        dns_provider.create_txt_record(request.agent_name, dns_value, ttl=300)
    except Exception:
        # DNS provisioning is best-effort, don't fail registration
        pass
    
    # Invalidate cache
    cache.delete(f"agent:{request.agent_name}")
    
    # Audit log
    log_audit_event(
        db,
        AuditEventType.REGISTER,
        agent_name=request.agent_name,
        metadata={"owner": request.owner, "capabilities": request.capabilities, "cert_type": cert_type.value}
    )
    
    return AgentResponse(
        agent_name=agent.agent_name,
        owner=agent.owner,
        capabilities=agent.capabilities,
        status=agent.status,
        cert_fingerprint=agent.cert_fingerprint,
        cert_serial_number=agent.cert_serial_number,  # v0.4: For OCSP
        cert_type=agent.cert_type,  # v0.4: Certificate type
        issued_at=agent.issued_at,
        expires_at=agent.expires_at,
        # v0.4: Public certificate fields
        public_cert_fingerprint=agent.public_cert_fingerprint,
        public_cert_serial_number=agent.public_cert_serial_number,
        public_cert_issued_at=agent.public_cert_issued_at,
        public_cert_expires_at=agent.public_cert_expires_at,
        public_cert_issuer=agent.public_cert_issuer,
        created_at=agent.created_at,
        updated_at=agent.updated_at
    )


@router.get("/{agent_name}/cert", response_model=AgentCertResponse)
def get_agent_certificate(agent_name: str, db: Session = Depends(get_db)):
    """Get agent certificate PEM (for verification purposes)"""
    agent = db.query(Agent).filter(Agent.agent_name == agent_name).first()
    if not agent:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Agent '{agent_name}' not found"
        )
    
    return AgentCertResponse(
        agent_name=agent.agent_name,
        cert_pem=agent.cert_pem,
        cert_fingerprint=agent.cert_fingerprint
    )


@router.get("/{agent_name}", response_model=AgentResponse)
def get_agent(agent_name: str, request: Request, db: Session = Depends(get_db)):
    """Get agent trust metadata (cached)"""
    # Check cache first
    cache_key = f"agent:{agent_name}"
    cached = cache.get(cache_key)
    if cached:
        return AgentResponse(**cached)
    
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
        "cert_type": agent.cert_type.value,  # v0.4: Certificate type
        "public_cert_fingerprint": agent.public_cert_fingerprint,  # v0.4: Public cert
        "public_cert_serial_number": agent.public_cert_serial_number,  # v0.4
        "public_cert_issued_at": agent.public_cert_issued_at.isoformat() if agent.public_cert_issued_at else None,  # v0.4
        "public_cert_expires_at": agent.public_cert_expires_at.isoformat() if agent.public_cert_expires_at else None,  # v0.4
        "public_cert_issuer": agent.public_cert_issuer,  # v0.4
        "cert_serial_number": agent.cert_serial_number,  # v0.4: For OCSP
        "issued_at": agent.issued_at,
        "expires_at": agent.expires_at,
        "created_at": agent.created_at,
        "updated_at": agent.updated_at
    }
    
    # Cache for 5 minutes
    cache.set(cache_key, response_data, ttl=300)
    
    return AgentResponse(
        agent_name=agent.agent_name,
        owner=agent.owner,
        capabilities=agent.capabilities,
        status=agent.status,
        cert_fingerprint=agent.cert_fingerprint,
        cert_serial_number=agent.cert_serial_number,  # v0.4: For OCSP
        cert_type=agent.cert_type,  # v0.4: Certificate type
        issued_at=agent.issued_at,
        expires_at=agent.expires_at,
        # v0.4: Public certificate fields
        public_cert_fingerprint=agent.public_cert_fingerprint,
        public_cert_serial_number=agent.public_cert_serial_number,
        public_cert_issued_at=agent.public_cert_issued_at,
        public_cert_expires_at=agent.public_cert_expires_at,
        public_cert_issuer=agent.public_cert_issuer,
        created_at=agent.created_at,
        updated_at=agent.updated_at
    )


@router.post("/{agent_name}/rotate", response_model=AgentRotateResponse)
def rotate_agent_certificate(agent_name: str, db: Session = Depends(get_db)):
    """Rotate agent certificate (issue new cert, update fingerprint)"""
    agent = db.query(Agent).filter(Agent.agent_name == agent_name).first()
    if not agent:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Agent '{agent_name}' not found"
        )
    
    if agent.status == AgentStatus.REVOKED:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Cannot rotate certificate for revoked agent '{agent_name}'"
        )
    
    # Issue new certificate
    try:
        private_key, cert, new_fingerprint = issue_agent_certificate(agent_name)
        cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode('utf-8')
        cert_serial_number = str(cert.serial_number)  # v0.4: Store serial for OCSP
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to issue certificate: {str(e)}"
        )
    
    # Update agent record
    now = datetime.utcnow()
    old_fingerprint = agent.cert_fingerprint
    agent.cert_fingerprint = new_fingerprint
    agent.cert_serial_number = cert_serial_number  # v0.4: For OCSP
    agent.cert_pem = cert_pem
    agent.issued_at = now
    agent.expires_at = now + timedelta(days=settings.cert_validity_days)
    agent.updated_at = now
    
    db.commit()
    db.refresh(agent)
    
    # Update DNS TXT record
    try:
        dns_value = f"fingerprint={new_fingerprint}"
        dns_provider.create_txt_record(agent_name, dns_value, ttl=300)
    except Exception:
        # DNS update is best-effort
        pass
    
    # Invalidate cache
    cache.delete(f"agent:{agent_name}")
    cache.delete(f"resolve:{agent_name}")
    
    # Audit log
    log_audit_event(
        db,
        AuditEventType.ROTATE,
        agent_name=agent_name,
        metadata={"old_fingerprint": old_fingerprint, "new_fingerprint": new_fingerprint}
    )
    
    return AgentRotateResponse(
        agent_name=agent.agent_name,
        new_cert_fingerprint=new_fingerprint,
        issued_at=agent.issued_at,
        expires_at=agent.expires_at
    )


@router.post("/{agent_name}/revoke", response_model=AgentRevokeResponse)
def revoke_agent(agent_name: str, db: Session = Depends(get_db)):
    """Revoke an agent (mark as revoked)"""
    agent = db.query(Agent).filter(Agent.agent_name == agent_name).first()
    if not agent:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Agent '{agent_name}' not found"
        )
    
    if agent.status == AgentStatus.REVOKED:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Agent '{agent_name}' is already revoked"
        )
    
    # Update status
    agent.status = AgentStatus.REVOKED
    agent.updated_at = datetime.utcnow()
    
    db.commit()
    db.refresh(agent)
    
    # Invalidate cache
    cache.delete(f"agent:{agent_name}")
    cache.delete(f"resolve:{agent_name}")
    
    # Audit log
    log_audit_event(
        db,
        AuditEventType.REVOKE,
        agent_name=agent_name,
        metadata={"fingerprint": agent.cert_fingerprint, "reason": "manual_revocation"}
    )
    
    return AgentRevokeResponse(
        agent_name=agent.agent_name,
        status=agent.status,
        revoked_at=agent.updated_at
    )
