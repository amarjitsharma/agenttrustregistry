"""Pydantic schemas for request/response models"""
from pydantic import BaseModel, Field, field_validator
from datetime import datetime
from typing import Optional, List, Dict, Any

from atr.core.models import AgentStatus, CertificateType


class AgentRegisterRequest(BaseModel):
    """Request to register a new agent"""
    agent_name: str = Field(..., description="Agent name (DNS-label format)")
    owner: str = Field(..., description="Owner identifier")
    capabilities: List[str] = Field(default_factory=list, description="List of capabilities")
    request_public_cert: bool = Field(default=False, description="Request public TLS certificate (Let's Encrypt) - v0.4")


class AgentResponse(BaseModel):
    """Agent metadata response"""
    agent_name: str
    owner: str
    capabilities: List[str]
    status: AgentStatus
    cert_fingerprint: str
    cert_serial_number: Optional[str] = None  # v0.4: For OCSP
    cert_type: CertificateType = CertificateType.PRIVATE  # v0.4: Certificate type
    issued_at: datetime
    expires_at: datetime
    # v0.4: Public certificate fields (optional)
    public_cert_fingerprint: Optional[str] = None
    public_cert_serial_number: Optional[str] = None
    public_cert_issued_at: Optional[datetime] = None
    public_cert_expires_at: Optional[datetime] = None
    public_cert_issuer: Optional[str] = None
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


# v0.3: Transparency Log Schemas
class LogEntryResponse(BaseModel):
    """Transparency log entry response"""
    entry_index: int
    event_type: str
    agent_name: Optional[str]
    event_data: Dict[str, Any]
    entry_hash: str
    tree_root_hash: Optional[str]
    created_at: datetime


class LogEntryListResponse(BaseModel):
    """List of log entries with pagination"""
    entries: List[LogEntryResponse]
    total: int
    limit: int
    offset: int
    latest_root_hash: Optional[str]


class InclusionProofResponse(BaseModel):
    """Inclusion proof response"""
    entry_index: int
    entry_hash: str
    root_hash: str
    proof: List[str]
    tree_size: int
    verified: bool
