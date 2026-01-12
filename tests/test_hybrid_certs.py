"""Tests for hybrid certificate architecture (v0.4)"""
import pytest
from datetime import datetime, timedelta
from sqlalchemy.orm import Session
from cryptography import x509
from cryptography.hazmat.primitives import serialization

from atr.core.db import Base, engine, SessionLocal
from atr.core.models import Agent, AgentStatus, CertificateType
from atr.pki.issue import issue_agent_certificate
from atr.pki.public_cert import issue_public_certificate
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


def test_register_with_private_cert_only(db: Session):
    """Test agent registration with private certificate only"""
    agent_name = "test-agent.example"
    
    # Issue private certificate
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
        cert_type=CertificateType.PRIVATE,
        issued_at=now,
        expires_at=now + timedelta(days=settings.cert_validity_days),
        created_at=now,
        updated_at=now
    )
    db.add(agent)
    db.commit()
    db.refresh(agent)
    
    # Verify
    assert agent.cert_type == CertificateType.PRIVATE
    assert agent.public_cert_fingerprint is None
    assert agent.public_cert_pem is None


def test_register_with_dual_certificates(db: Session):
    """Test agent registration with both private and public certificates"""
    agent_name = "test-agent.example"
    
    # Issue private certificate
    private_key, cert, fingerprint = issue_agent_certificate(agent_name)
    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode('utf-8')
    
    # Issue public certificate (requires ACME to be enabled in config)
    # For testing, we'll mock this
    try:
        public_key, public_cert, public_fingerprint = issue_public_certificate(agent_name)
        public_cert_pem = public_cert.public_bytes(serialization.Encoding.PEM).decode('utf-8')
        public_cert_issued_at = datetime.utcnow()
        public_cert_expires_at = public_cert.not_valid_after.replace(tzinfo=None)
    except ValueError:
        # ACME not enabled, skip this test
        pytest.skip("ACME not enabled - cannot issue public certificates")
        return
    
    now = datetime.utcnow()
    agent = Agent(
        agent_name=agent_name,
        owner="test-owner",
        capabilities=[],
        status=AgentStatus.ACTIVE,
        cert_fingerprint=fingerprint,
        cert_pem=cert_pem,
        cert_type=CertificateType.DUAL,
        # Public certificate fields
        public_cert_fingerprint=public_fingerprint,
        public_cert_pem=public_cert_pem,
        public_cert_serial_number=str(public_cert.serial_number),
        public_cert_issued_at=public_cert_issued_at,
        public_cert_expires_at=public_cert_expires_at,
        public_cert_issuer="Let's Encrypt",
        issued_at=now,
        expires_at=now + timedelta(days=settings.cert_validity_days),
        created_at=now,
        updated_at=now
    )
    db.add(agent)
    db.commit()
    db.refresh(agent)
    
    # Verify
    assert agent.cert_type == CertificateType.DUAL
    assert agent.public_cert_fingerprint == public_fingerprint
    assert agent.public_cert_pem is not None
    assert agent.public_cert_issuer == "Let's Encrypt"
    assert agent.public_cert_fingerprint != agent.cert_fingerprint  # Different fingerprints


def test_verify_private_certificate(db: Session):
    """Test verification of private certificate"""
    agent_name = "test-agent.example"
    
    # Register agent with private cert
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
        cert_type=CertificateType.PRIVATE,
        issued_at=now,
        expires_at=now + timedelta(days=settings.cert_validity_days),
        created_at=now,
        updated_at=now
    )
    db.add(agent)
    db.commit()
    
    # Verify certificate can be found by private fingerprint
    found_agent = db.query(Agent).filter(Agent.cert_fingerprint == fingerprint).first()
    assert found_agent is not None
    assert found_agent.cert_type == CertificateType.PRIVATE


def test_verify_public_certificate(db: Session):
    """Test verification of public certificate"""
    agent_name = "test-agent.example"
    
    # Issue private certificate
    private_key, cert, fingerprint = issue_agent_certificate(agent_name)
    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode('utf-8')
    
    # Issue public certificate
    try:
        public_key, public_cert, public_fingerprint = issue_public_certificate(agent_name)
        public_cert_pem = public_cert.public_bytes(serialization.Encoding.PEM).decode('utf-8')
    except ValueError:
        pytest.skip("ACME not enabled - cannot issue public certificates")
        return
    
    now = datetime.utcnow()
    agent = Agent(
        agent_name=agent_name,
        owner="test-owner",
        capabilities=[],
        status=AgentStatus.ACTIVE,
        cert_fingerprint=fingerprint,
        cert_pem=cert_pem,
        cert_type=CertificateType.DUAL,
        public_cert_fingerprint=public_fingerprint,
        public_cert_pem=public_cert_pem,
        public_cert_serial_number=str(public_cert.serial_number),
        public_cert_issued_at=now,
        public_cert_expires_at=public_cert.not_valid_after.replace(tzinfo=None),
        public_cert_issuer="Let's Encrypt",
        issued_at=now,
        expires_at=now + timedelta(days=settings.cert_validity_days),
        created_at=now,
        updated_at=now
    )
    db.add(agent)
    db.commit()
    
    # Verify certificate can be found by public fingerprint
    found_agent = db.query(Agent).filter(Agent.public_cert_fingerprint == public_fingerprint).first()
    assert found_agent is not None
    assert found_agent.cert_type == CertificateType.DUAL
    assert found_agent.public_cert_fingerprint == public_fingerprint


def test_verify_dual_certificate_linking(db: Session):
    """Test that private and public certificates are properly linked"""
    agent_name = "test-agent.example"
    
    # Issue both certificates
    private_key, cert, fingerprint = issue_agent_certificate(agent_name)
    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode('utf-8')
    
    try:
        public_key, public_cert, public_fingerprint = issue_public_certificate(agent_name)
        public_cert_pem = public_cert.public_bytes(serialization.Encoding.PEM).decode('utf-8')
    except ValueError:
        pytest.skip("ACME not enabled - cannot issue public certificates")
        return
    
    now = datetime.utcnow()
    agent = Agent(
        agent_name=agent_name,
        owner="test-owner",
        capabilities=[],
        status=AgentStatus.ACTIVE,
        cert_fingerprint=fingerprint,
        cert_pem=cert_pem,
        cert_type=CertificateType.DUAL,
        public_cert_fingerprint=public_fingerprint,
        public_cert_pem=public_cert_pem,
        public_cert_serial_number=str(public_cert.serial_number),
        public_cert_issued_at=now,
        public_cert_expires_at=public_cert.not_valid_after.replace(tzinfo=None),
        public_cert_issuer="Let's Encrypt",
        issued_at=now,
        expires_at=now + timedelta(days=settings.cert_validity_days),
        created_at=now,
        updated_at=now
    )
    db.add(agent)
    db.commit()
    
    # Verify both certificates are linked to the same agent
    agent_by_private = db.query(Agent).filter(Agent.cert_fingerprint == fingerprint).first()
    agent_by_public = db.query(Agent).filter(Agent.public_cert_fingerprint == public_fingerprint).first()
    
    assert agent_by_private is not None
    assert agent_by_public is not None
    assert agent_by_private.agent_name == agent_by_public.agent_name
    assert agent_by_private.cert_type == CertificateType.DUAL
