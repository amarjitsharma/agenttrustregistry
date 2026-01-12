"""Tests for security monitoring (v0.4)"""
import pytest
from datetime import datetime, timedelta
from sqlalchemy.orm import Session

from atr.core.db import Base
from atr.core.models import Agent, AgentStatus, AuditEvent, AuditEventType, CertificateType
from atr.security.monitoring import SecurityMonitor
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


def test_security_monitor_initialization(db: Session):
    """Test security monitor initialization"""
    monitor = SecurityMonitor(db)
    assert monitor is not None
    assert monitor.alert_thresholds is not None


def test_security_summary(db: Session):
    """Test security summary generation"""
    monitor = SecurityMonitor(db)
    
    # Create some test data
    from atr.pki.issue import issue_agent_certificate
    from cryptography.hazmat.primitives import serialization
    
    agent_name = "test-agent.example"
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
        expires_at=now + timedelta(days=30),
        created_at=now,
        updated_at=now
    )
    db.add(agent)
    db.commit()
    
    # Create audit events
    from atr.core.audit import log_audit_event
    log_audit_event(db, AuditEventType.REGISTER, agent_name=agent_name)
    log_audit_event(db, AuditEventType.VERIFY, agent_name=agent_name)
    
    # Get summary
    summary = monitor.get_security_summary(time_window=timedelta(hours=24))
    
    assert "event_counts" in summary
    assert "agent_counts" in summary
    assert "anomalies_detected" in summary
    assert summary["agent_counts"]["active"] >= 1


def test_anomaly_detection_disabled(db: Session):
    """Test that anomaly detection returns empty when disabled"""
    original_setting = settings.anomaly_detection_enabled
    settings.anomaly_detection_enabled = False
    
    try:
        monitor = SecurityMonitor(db)
        anomalies = monitor.detect_anomalies()
        assert anomalies == []
    finally:
        settings.anomaly_detection_enabled = original_setting
