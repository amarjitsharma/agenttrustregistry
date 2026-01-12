"""Registration Authority (RA) Service Layer (v0.4)

This module provides a service layer for agent registration, certificate management,
and lifecycle operations. It abstracts the business logic from the API endpoints
and provides a foundation for workflow orchestration and policy enforcement.
"""
from typing import Optional, Dict, Any, List
from datetime import datetime, timedelta
from sqlalchemy.orm import Session

from atr.core.models import Agent, AgentStatus, CertificateType, AuditEventType
from atr.core.validators import validate_agent_name
from atr.core.audit import log_audit_event
from atr.pki.issue import issue_agent_certificate
from atr.pki.public_cert import issue_public_certificate
from atr.pki.fingerprints import compute_fingerprint
from atr.core.config import settings
from atr.dns.providers import get_dns_provider
from atr.core.cache import get_cache


class RegistrationAuthority:
    """Registration Authority service for agent lifecycle management"""
    
    def __init__(self, db: Session):
        self.db = db
        self.cache = get_cache()
        self.dns_provider = get_dns_provider()
    
    def register_agent(
        self,
        agent_name: str,
        owner: str,
        capabilities: List[str],
        request_public_cert: bool = False
    ) -> Agent:
        """
        Register a new agent with certificate issuance.
        
        Args:
            agent_name: Agent name (DNS-label format)
            owner: Owner identifier
            capabilities: List of agent capabilities
            request_public_cert: Whether to request a public certificate
            
        Returns:
            Agent object
            
        Raises:
            ValueError: If validation fails
            Exception: If registration fails
        """
        # Validate agent name
        validation_error = validate_agent_name(agent_name)
        if validation_error:
            raise ValueError(validation_error)
        
        # Check if agent already exists
        existing = self.db.query(Agent).filter(Agent.agent_name == agent_name).first()
        if existing:
            raise ValueError(f"Agent '{agent_name}' already exists")
        
        # Issue private certificate (always)
        try:
            from cryptography.hazmat.primitives import serialization
            private_key, cert, fingerprint = issue_agent_certificate(agent_name)
            cert_pem = cert.public_bytes(
                serialization.Encoding.PEM
            ).decode('utf-8')
            cert_serial_number = str(cert.serial_number)
        except Exception as e:
            raise Exception(f"Failed to issue private certificate: {str(e)}")
        
        # Initialize certificate type and public cert fields
        cert_type = CertificateType.PRIVATE
        public_cert_pem = None
        public_cert_fingerprint = None
        public_cert_serial_number = None
        public_cert_issued_at = None
        public_cert_expires_at = None
        public_cert_issuer = None
        
        # Issue public certificate if requested
        if request_public_cert:
            if not settings.acme_enabled:
                # Continue with private cert only if ACME not enabled
                pass
            else:
                try:
                    from cryptography.hazmat.primitives import serialization as pub_serialization
                    public_key, public_cert, public_fingerprint = issue_public_certificate(agent_name)
                    public_cert_pem = public_cert.public_bytes(
                        pub_serialization.Encoding.PEM
                    ).decode('utf-8')
                    public_cert_serial_number = str(public_cert.serial_number)
                    public_cert_issued_at = datetime.utcnow()
                    public_cert_expires_at = public_cert.not_valid_after.replace(tzinfo=None)
                    public_cert_fingerprint = public_fingerprint
                    public_cert_issuer = "Let's Encrypt"
                    cert_type = CertificateType.DUAL
                except Exception as e:
                    # If public cert issuance fails, continue with private cert only
                    pass
        
        # Create agent record
        now = datetime.utcnow()
        agent = Agent(
            agent_name=agent_name,
            owner=owner,
            capabilities=capabilities,
            status=AgentStatus.ACTIVE,
            cert_fingerprint=fingerprint,
            cert_serial_number=cert_serial_number,
            cert_pem=cert_pem,
            cert_type=cert_type,
            issued_at=now,
            expires_at=now + timedelta(days=settings.cert_validity_days),
            public_cert_fingerprint=public_cert_fingerprint,
            public_cert_pem=public_cert_pem,
            public_cert_serial_number=public_cert_serial_number,
            public_cert_issued_at=public_cert_issued_at,
            public_cert_expires_at=public_cert_expires_at,
            public_cert_issuer=public_cert_issuer,
            created_at=now,
            updated_at=now
        )
        
        self.db.add(agent)
        self.db.commit()
        self.db.refresh(agent)
        
        # Create DNS TXT record (best-effort)
        try:
            dns_value = f"fingerprint={fingerprint}"
            self.dns_provider.create_txt_record(agent_name, dns_value, ttl=300)
        except Exception:
            pass
        
        # Invalidate cache
        self.cache.delete(f"agent:{agent_name}")
        
        # Audit log
        log_audit_event(
            self.db,
            AuditEventType.REGISTER,
            agent_name=agent_name,
            metadata={
                "owner": owner,
                "capabilities": capabilities,
                "cert_type": cert_type.value
            }
        )
        
        return agent
    
    def rotate_certificate(self, agent_name: str) -> Agent:
        """
        Rotate an agent's certificate.
        
        Args:
            agent_name: Agent name
            
        Returns:
            Updated Agent object
            
        Raises:
            ValueError: If agent not found or cannot be rotated
        """
        agent = self.db.query(Agent).filter(Agent.agent_name == agent_name).first()
        if not agent:
            raise ValueError(f"Agent '{agent_name}' not found")
        
        if agent.status != AgentStatus.ACTIVE:
            raise ValueError(f"Agent '{agent_name}' is not active and cannot be rotated")
        
        # Issue new private certificate
        try:
            from cryptography.hazmat.primitives import serialization
            private_key, cert, fingerprint = issue_agent_certificate(agent_name)
            cert_pem = cert.public_bytes(
                serialization.Encoding.PEM
            ).decode('utf-8')
            cert_serial_number = str(cert.serial_number)
        except Exception as e:
            raise Exception(f"Failed to issue new certificate: {str(e)}")
        
        # Update agent
        now = datetime.utcnow()
        agent.cert_fingerprint = fingerprint
        agent.cert_pem = cert_pem
        agent.cert_serial_number = cert_serial_number
        agent.issued_at = now
        agent.expires_at = now + timedelta(days=settings.cert_validity_days)
        agent.updated_at = now
        
        self.db.commit()
        self.db.refresh(agent)
        
        # Update DNS TXT record
        try:
            dns_value = f"fingerprint={fingerprint}"
            self.dns_provider.create_txt_record(agent_name, dns_value, ttl=300)
        except Exception:
            pass
        
        # Invalidate cache
        self.cache.delete(f"agent:{agent_name}")
        
        # Audit log
        log_audit_event(
            self.db,
            AuditEventType.ROTATE,
            agent_name=agent_name,
            metadata={"new_fingerprint": fingerprint}
        )
        
        return agent
    
    def revoke_agent(self, agent_name: str) -> Agent:
        """
        Revoke an agent's certificate.
        
        Args:
            agent_name: Agent name
            
        Returns:
            Updated Agent object
            
        Raises:
            ValueError: If agent not found
        """
        agent = self.db.query(Agent).filter(Agent.agent_name == agent_name).first()
        if not agent:
            raise ValueError(f"Agent '{agent_name}' not found")
        
        agent.status = AgentStatus.REVOKED
        agent.updated_at = datetime.utcnow()
        
        self.db.commit()
        self.db.refresh(agent)
        
        # Invalidate cache
        self.cache.delete(f"agent:{agent_name}")
        
        # Audit log
        log_audit_event(
            self.db,
            AuditEventType.REVOKE,
            agent_name=agent_name,
            metadata={}
        )
        
        return agent
