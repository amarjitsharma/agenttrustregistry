"""Pydantic schemas for request/response models"""
from pydantic import BaseModel, Field, field_validator
from datetime import datetime
from typing import Optional, List, Dict, Any

from atr.core.models import AgentStatus


class AgentRegisterRequest(BaseModel):
    """Request to register a new agent"""
    agent_name: str = Field(..., description="Agent name (DNS-label format)")
    owner: str = Field(..., description="Owner identifier")
    capabilities: List[str] = Field(default_factory=list, description="List of capabilities")


class AgentResponse(BaseModel):
    """Agent metadata response"""
    agent_name: str
    owner: str
    capabilities: List[str]
    status: AgentStatus
    cert_fingerprint: str
    issued_at: datetime
    expires_at: datetime
    created_at: datetime
    updated_at: datetime


class AgentRotateResponse(BaseModel):
    """Response after certificate rotation"""
    agent_name: str
    new_cert_fingerprint: str
    issued_at: datetime
    expires_at: datetime


class AgentRevokeResponse(BaseModel):
    """Response after revocation"""
    agent_name: str
    status: AgentStatus
    revoked_at: datetime


class VerifyCertRequest(BaseModel):
    """Request to verify a certificate"""
    cert_pem: str = Field(..., description="PEM-encoded certificate")


class VerifyCertResponse(BaseModel):
    """Certificate verification response"""
    verified: bool
    agent_name: Optional[str] = None
    status: Optional[AgentStatus] = None
    expires_at: Optional[datetime] = None
    reason: Optional[str] = None


class ResolveResponse(BaseModel):
    """Agent resolution response"""
    agent_name: str
    owner: str
    capabilities: List[str]
    status: AgentStatus
    cert_fingerprint: str
    expires_at: datetime


class AgentListResponse(BaseModel):
    """List of agents with pagination metadata"""
    agents: List[AgentResponse]
    total: int
    limit: int
    offset: int


class AgentCertResponse(BaseModel):
    """Agent certificate PEM response"""
    agent_name: str
    cert_pem: str
    cert_fingerprint: str
