"""Tests for RA Certificate Renewal (v0.4)"""
import pytest
from datetime import datetime, timedelta
from sqlalchemy.orm import Session

from atr.core.db import Base
from atr.core.models import Agent, AgentStatus
from atr.ra.service import RegistrationAuthority
from atr.ra.renewal import CertificateRenewalService
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


def test_renewal_find_expiring_certificates(db: Session):
    """Test finding expiring certificates"""
    ra = RegistrationAuthority(db)
    renewal = CertificateRenewalService(db)
    
    # Register agent with certificate expiring soon
    agent_name = "test-agent.example"
    agent = ra.register_agent(agent_name, "test-owner", [])
    
    # Manually set expiration to be soon (7 days)
    agent.expires_at = datetime.utcnow() + timedelta(days=7)
    db.commit()
    
    # Find expiring certificates
    expiring = renewal.find_certificates_expiring_soon(days_ahead=7)
    
    assert len(expiring) >= 1
    assert any(a.agent_name == agent_name for a in expiring)


def test_renewal_find_expired_certificates(db: Session):
    """Test finding expired certificates"""
    ra = RegistrationAuthority(db)
    renewal = CertificateRenewalService(db)
    
    # Register agent
    agent_name = "test-agent.example"
    agent = ra.register_agent(agent_name, "test-owner", [])
    
    # Manually set expiration to past
    agent.expires_at = datetime.utcnow() - timedelta(days=1)
    db.commit()
    
    # Find expired certificates
    expired = renewal.find_expired_certificates()
    
    assert len(expired) >= 1
    assert any(a.agent_name == agent_name for a in expired)


def test_renewal_renew_certificate(db: Session):
    """Test renewing a certificate"""
    ra = RegistrationAuthority(db)
    renewal = CertificateRenewalService(db)
    
    # Register agent
    agent_name = "test-agent.example"
    agent = ra.register_agent(agent_name, "test-owner", [])
    old_fingerprint = agent.cert_fingerprint
    old_expires_at = agent.expires_at
    
    # Renew certificate
    result = renewal.renew_certificate(agent_name)
    
    assert result["success"] is True
    assert result["agent_name"] == agent_name
    assert result["new_fingerprint"] != old_fingerprint
    
    # Verify agent was updated
    db.refresh(agent)
    assert agent.cert_fingerprint != old_fingerprint
    assert agent.expires_at > old_expires_at


def test_renewal_dry_run(db: Session):
    """Test renewal dry run"""
    ra = RegistrationAuthority(db)
    renewal = CertificateRenewalService(db)
    
    # Register agent
    agent_name = "test-agent.example"
    agent = ra.register_agent(agent_name, "test-owner", [])
    
    # Set expiration to soon
    agent.expires_at = datetime.utcnow() + timedelta(days=5)
    db.commit()
    old_fingerprint = agent.cert_fingerprint
    
    # Dry run renewal
    result = renewal.renew_expiring_certificates(days_ahead=7, dry_run=True)
    
    assert result["dry_run"] is True
    assert result["total_found"] >= 1
    assert len(result["renewed"]) > 0
    
    # Verify certificate was NOT actually renewed
    db.refresh(agent)
    assert agent.cert_fingerprint == old_fingerprint


def test_renewal_renew_expiring_certificates(db: Session):
    """Test renewing all expiring certificates"""
    ra = RegistrationAuthority(db)
    renewal = CertificateRenewalService(db)
    
    # Register multiple agents
    for i in range(3):
        agent_name = f"test-agent-{i}.example"
        agent = ra.register_agent(agent_name, "test-owner", [])
        # Set expiration to soon
        agent.expires_at = datetime.utcnow() + timedelta(days=5)
        db.commit()
    
    # Renew all expiring certificates
    result = renewal.renew_expiring_certificates(days_ahead=7, dry_run=False)
    
    assert result["dry_run"] is False
    assert result["total_found"] >= 3
    assert len(result["renewed"]) >= 3
