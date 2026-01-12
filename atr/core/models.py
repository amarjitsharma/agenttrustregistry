"""SQLAlchemy models"""
from sqlalchemy import Column, String, DateTime, Text, JSON, Enum as SQLEnum
from sqlalchemy.sql import func
from datetime import datetime
import enum

from atr.core.db import Base


class AgentStatus(str, enum.Enum):
    """Agent status enumeration"""
    ACTIVE = "active"
    REVOKED = "revoked"


class CertificateType(str, enum.Enum):
    """Certificate type enumeration (v0.4: Hybrid Certificate Architecture)"""
    PRIVATE = "private"  # Private CA-issued certificate (default)
    PUBLIC = "public"   # Public CA-issued certificate (Let's Encrypt, etc.)
    DUAL = "dual"       # Both private and public certificates


class Agent(Base):
    """Agent registry model"""
    __tablename__ = "agents"
    
    agent_name = Column(String(255), primary_key=True, index=True)
    owner = Column(String(255), nullable=False)
    capabilities = Column(JSON, default=list)
    status = Column(SQLEnum(AgentStatus), default=AgentStatus.ACTIVE, nullable=False)
    
    # Private certificate fields (existing)
    cert_fingerprint = Column(String(64), nullable=False, index=True)
    cert_serial_number = Column(String(64), nullable=True, index=True)  # v0.4: For OCSP
    cert_pem = Column(Text, nullable=False)
    issued_at = Column(DateTime, nullable=False)
    expires_at = Column(DateTime, nullable=False)
    
    # v0.4: Public certificate fields (optional, for hybrid architecture)
    cert_type = Column(SQLEnum(CertificateType), default=CertificateType.PRIVATE, nullable=False)
    public_cert_fingerprint = Column(String(64), nullable=True, index=True)
    public_cert_pem = Column(Text, nullable=True)
    public_cert_serial_number = Column(String(64), nullable=True, index=True)
    public_cert_issued_at = Column(DateTime, nullable=True)
    public_cert_expires_at = Column(DateTime, nullable=True)
    public_cert_issuer = Column(String(255), nullable=True)  # e.g., "Let's Encrypt"
    
    created_at = Column(DateTime, server_default=func.now(), nullable=False)
    updated_at = Column(DateTime, server_default=func.now(), onupdate=func.now(), nullable=False)


class AuditEventType(str, enum.Enum):
    """Audit event types"""
    REGISTER = "register"
    ROTATE = "rotate"
    REVOKE = "revoke"
    VERIFY = "verify"


class AuditEvent(Base):
    """Audit log model"""
    __tablename__ = "audit_events"
    
    id = Column(String(36), primary_key=True)  # UUID as string
    event_type = Column(SQLEnum(AuditEventType), nullable=False, index=True)
    actor = Column(String(255), nullable=True)
    agent_name = Column(String(255), nullable=True, index=True)
    event_metadata = Column("metadata", JSON, default=dict)  # Column name is "metadata" in DB, but attribute is "event_metadata"
    timestamp = Column(DateTime, server_default=func.now(), nullable=False, index=True)
