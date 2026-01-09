"""Agent lifecycle routes"""
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from datetime import datetime, timedelta
from cryptography.hazmat.primitives import serialization

from atr.core.db import get_db
from atr.core.models import Agent, AgentStatus
from atr.core.schemas import (
    AgentRegisterRequest,
    AgentResponse,
    AgentRotateResponse,
    AgentRevokeResponse,
)
from atr.core.validators import validate_agent_name
from atr.core.audit import log_audit_event, AuditEventType
from atr.pki.issue import issue_agent_certificate
from atr.pki.fingerprints import compute_fingerprint
from atr.core.config import settings

router = APIRouter(prefix="/v1/agents", tags=["agents"])


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
    
    # Check if agent already exists
    existing = db.query(Agent).filter(Agent.agent_name == request.agent_name).first()
    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Agent '{request.agent_name}' already exists"
        )
    
    # Issue certificate
    try:
        private_key, cert, fingerprint = issue_agent_certificate(request.agent_name)
        cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode('utf-8')
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to issue certificate: {str(e)}"
        )
    
    # Create agent record
    now = datetime.utcnow()
    agent = Agent(
        agent_name=request.agent_name,
        owner=request.owner,
        capabilities=request.capabilities,
        status=AgentStatus.ACTIVE,
        cert_fingerprint=fingerprint,
        cert_pem=cert_pem,
        issued_at=now,
        expires_at=now + timedelta(days=settings.cert_validity_days),
        created_at=now,
        updated_at=now
    )
    
    db.add(agent)
    db.commit()
    db.refresh(agent)
    
    # Audit log
    log_audit_event(
        db,
        AuditEventType.REGISTER,
        agent_name=request.agent_name,
        metadata={"owner": request.owner, "capabilities": request.capabilities}
    )
    
    return AgentResponse(
        agent_name=agent.agent_name,
        owner=agent.owner,
        capabilities=agent.capabilities,
        status=agent.status,
        cert_fingerprint=agent.cert_fingerprint,
        issued_at=agent.issued_at,
        expires_at=agent.expires_at,
        created_at=agent.created_at,
        updated_at=agent.updated_at
    )


@router.get("/{agent_name}", response_model=AgentResponse)
def get_agent(agent_name: str, db: Session = Depends(get_db)):
    """Get agent trust metadata"""
    agent = db.query(Agent).filter(Agent.agent_name == agent_name).first()
    if not agent:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Agent '{agent_name}' not found"
        )
    
    return AgentResponse(
        agent_name=agent.agent_name,
        owner=agent.owner,
        capabilities=agent.capabilities,
        status=agent.status,
        cert_fingerprint=agent.cert_fingerprint,
        issued_at=agent.issued_at,
        expires_at=agent.expires_at,
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
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to issue certificate: {str(e)}"
        )
    
    # Update agent record
    now = datetime.utcnow()
    old_fingerprint = agent.cert_fingerprint
    agent.cert_fingerprint = new_fingerprint
    agent.cert_pem = cert_pem
    agent.issued_at = now
    agent.expires_at = now + timedelta(days=settings.cert_validity_days)
    agent.updated_at = now
    
    db.commit()
    db.refresh(agent)
    
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
    
    # Audit log
    log_audit_event(
        db,
        AuditEventType.REVOKE,
        agent_name=agent_name,
        metadata={"fingerprint": agent.cert_fingerprint}
    )
    
    return AgentRevokeResponse(
        agent_name=agent.agent_name,
        status=agent.status,
        revoked_at=agent.updated_at
    )
