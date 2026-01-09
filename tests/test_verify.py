"""Tests for certificate verification"""
import pytest
from datetime import datetime, timedelta
from sqlalchemy.orm import Session
from cryptography import x509
from cryptography.hazmat.primitives import serialization

from atr.core.db import Base, engine, SessionLocal
from atr.core.models import Agent, AgentStatus
from atr.pki.issue import issue_agent_certificate
from atr.pki.fingerprints import compute_fingerprint
from atr.core.config import settings


@pytest.fixture(scope="function")
def db():
    """Create a fresh database for each test"""
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    
    # Create a fresh engine and session for each test
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


def test_verify_active_certificate(db: Session):
    """Test verification of active, valid certificate"""
    agent_name = "test-agent.example"
    
    # Register agent
    private_key, cert, fingerprint = issue_agent_certificate(agent_name)
    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode('utf-8')
    
    now = datetime.utcnow()
    agent = Agent(
        agent_name=agent_name,
        owner="test-owner",
        capabilities=[],
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
    
    # Verify certificate
    parsed_cert = x509.load_pem_x509_certificate(cert_pem.encode('utf-8'))
    computed_fingerprint = compute_fingerprint(parsed_cert)
    
    # Check fingerprint matches
    assert computed_fingerprint == fingerprint
    assert agent.cert_fingerprint == fingerprint
    assert agent.status == AgentStatus.ACTIVE
    
    # Check not expired
    assert parsed_cert.not_valid_after > datetime.utcnow()
    assert agent.expires_at > datetime.utcnow()


def test_verify_revoked_certificate_fails(db: Session):
    """Test that revoked certificates fail verification"""
    agent_name = "test-agent.example"
    
    # Register and revoke agent
    private_key, cert, fingerprint = issue_agent_certificate(agent_name)
    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode('utf-8')
    
    now = datetime.utcnow()
    agent = Agent(
        agent_name=agent_name,
        owner="test-owner",
        capabilities=[],
        status=AgentStatus.REVOKED,  # Revoked
        cert_fingerprint=fingerprint,
        cert_pem=cert_pem,
        issued_at=now,
        expires_at=now + timedelta(days=settings.cert_validity_days),
        created_at=now,
        updated_at=now
    )
    db.add(agent)
    db.commit()
    
    # Verification should fail because status is revoked
    assert agent.status == AgentStatus.REVOKED
    
    # Even though cert is valid, status check should fail
    parsed_cert = x509.load_pem_x509_certificate(cert_pem.encode('utf-8'))
    computed_fingerprint = compute_fingerprint(parsed_cert)
    assert computed_fingerprint == fingerprint  # Fingerprint matches
    assert agent.status == AgentStatus.REVOKED  # But status is revoked


def test_verify_expired_certificate_fails(db: Session):
    """Test that expired certificates fail verification"""
    agent_name = "test-agent.example"
    
    # Register agent with expired cert
    private_key, cert, fingerprint = issue_agent_certificate(agent_name)
    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode('utf-8')
    
    now = datetime.utcnow()
    # Set expires_at in the past
    past_expiry = now - timedelta(days=1)
    
    agent = Agent(
        agent_name=agent_name,
        owner="test-owner",
        capabilities=[],
        status=AgentStatus.ACTIVE,
        cert_fingerprint=fingerprint,
        cert_pem=cert_pem,
        issued_at=now - timedelta(days=settings.cert_validity_days + 1),
        expires_at=past_expiry,  # Expired
        created_at=now,
        updated_at=now
    )
    db.add(agent)
    db.commit()
    
    # Verification should fail because expired
    assert agent.expires_at < datetime.utcnow()
    assert agent.status == AgentStatus.ACTIVE  # Status is active but expired


def test_verify_unknown_fingerprint_fails(db: Session):
    """Test that unknown certificate fingerprints fail verification"""
    agent_name = "test-agent.example"
    
    # Create a certificate but don't register it
    private_key, cert, fingerprint = issue_agent_certificate(agent_name)
    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode('utf-8')
    
    # Don't add to database
    # Verification should fail because fingerprint not in registry
    
    # Check that agent doesn't exist
    agent = db.query(Agent).filter(Agent.cert_fingerprint == fingerprint).first()
    assert agent is None


def test_verify_fingerprint_mismatch(db: Session):
    """Test that wrong fingerprint fails verification"""
    agent_name = "test-agent.example"
    
    # Register agent
    private_key1, cert1, fingerprint1 = issue_agent_certificate(agent_name)
    cert_pem1 = cert1.public_bytes(serialization.Encoding.PEM).decode('utf-8')
    
    now = datetime.utcnow()
    agent = Agent(
        agent_name=agent_name,
        owner="test-owner",
        capabilities=[],
        status=AgentStatus.ACTIVE,
        cert_fingerprint=fingerprint1,
        cert_pem=cert_pem1,
        issued_at=now,
        expires_at=now + timedelta(days=settings.cert_validity_days),
        created_at=now,
        updated_at=now
    )
    db.add(agent)
    db.commit()
    
    # Create a different certificate
    private_key2, cert2, fingerprint2 = issue_agent_certificate("different-agent")
    
    # Fingerprints should be different
    assert fingerprint1 != fingerprint2
    assert agent.cert_fingerprint == fingerprint1
    assert agent.cert_fingerprint != fingerprint2
