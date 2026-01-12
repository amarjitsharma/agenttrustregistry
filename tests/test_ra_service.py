"""Tests for RA Service Layer (v0.4)"""
import pytest
from datetime import datetime, timedelta
from sqlalchemy.orm import Session

from atr.core.db import Base
from atr.core.models import Agent, AgentStatus, CertificateType
from atr.ra.service import RegistrationAuthority
from atr.core.config import settings


@pytest.fixture(scope="function")
def db():
    """Create a fresh database for each test"""
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    
    test_engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=test_engine)
    TestSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)
    db = TestSessionLocal()
    try:
        yield db
    finally:
        db.close()
        Base.metadata.drop_all(bind=test_engine)
        test_engine.dispose()


def test_ra_register_agent(db: Session):
    """Test RA service registration"""
    ra = RegistrationAuthority(db)
    
    agent_name = "test-agent.example"
    owner = "test-owner"
    capabilities = ["read", "write"]
    
    agent = ra.register_agent(agent_name, owner, capabilities, request_public_cert=False)
    
    assert agent.agent_name == agent_name
    assert agent.owner == owner
    assert agent.capabilities == capabilities
    assert agent.status == AgentStatus.ACTIVE
    assert agent.cert_type == CertificateType.PRIVATE
    assert agent.cert_fingerprint is not None
    assert agent.cert_pem is not None


def test_ra_register_agent_duplicate(db: Session):
    """Test RA service registration with duplicate agent name"""
    ra = RegistrationAuthority(db)
    
    agent_name = "test-agent.example"
    owner = "test-owner"
    
    # Register first time
    ra.register_agent(agent_name, owner, [])
    
    # Try to register again - should fail
    with pytest.raises(ValueError, match="already exists"):
        ra.register_agent(agent_name, owner, [])


def test_ra_rotate_certificate(db: Session):
    """Test RA service certificate rotation"""
    ra = RegistrationAuthority(db)
    
    agent_name = "test-agent.example"
    owner = "test-owner"
    
    # Register agent
    agent = ra.register_agent(agent_name, owner, [])
    old_fingerprint = agent.cert_fingerprint
    old_expires_at = agent.expires_at
    
    # Rotate certificate
    updated_agent = ra.rotate_certificate(agent_name)
    
    assert updated_agent.agent_name == agent_name
    assert updated_agent.cert_fingerprint != old_fingerprint
    assert updated_agent.expires_at > old_expires_at


def test_ra_rotate_certificate_not_found(db: Session):
    """Test RA service certificate rotation for non-existent agent"""
    ra = RegistrationAuthority(db)
    
    with pytest.raises(ValueError, match="not found"):
        ra.rotate_certificate("non-existent-agent.example")


def test_ra_rotate_certificate_revoked(db: Session):
    """Test RA service certificate rotation for revoked agent"""
    ra = RegistrationAuthority(db)
    
    agent_name = "test-agent.example"
    owner = "test-owner"
    
    # Register and revoke agent
    agent = ra.register_agent(agent_name, owner, [])
    ra.revoke_agent(agent_name)
    
    # Try to rotate - should fail
    with pytest.raises(ValueError, match="not active"):
        ra.rotate_certificate(agent_name)


def test_ra_revoke_agent(db: Session):
    """Test RA service agent revocation"""
    ra = RegistrationAuthority(db)
    
    agent_name = "test-agent.example"
    owner = "test-owner"
    
    # Register agent
    agent = ra.register_agent(agent_name, owner, [])
    assert agent.status == AgentStatus.ACTIVE
    
    # Revoke agent
    revoked_agent = ra.revoke_agent(agent_name)
    assert revoked_agent.status == AgentStatus.REVOKED


def test_ra_revoke_agent_not_found(db: Session):
    """Test RA service agent revocation for non-existent agent"""
    ra = RegistrationAuthority(db)
    
    with pytest.raises(ValueError, match="not found"):
        ra.revoke_agent("non-existent-agent.example")
