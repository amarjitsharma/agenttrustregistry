"""Audit logging utilities"""
import uuid
from datetime import datetime
from sqlalchemy.orm import Session
from typing import Optional, Dict, Any

from atr.core.models import AuditEvent, AuditEventType


def log_audit_event(
    db: Session,
    event_type: AuditEventType,
    agent_name: Optional[str] = None,
    actor: Optional[str] = None,
    metadata: Optional[Dict[str, Any]] = None
) -> AuditEvent:
    """Create and persist an audit event"""
    event = AuditEvent(
        id=str(uuid.uuid4()),
        event_type=event_type,
        agent_name=agent_name,
        actor=actor,
        event_metadata=metadata or {}  # Use event_metadata attribute name
    )
    db.add(event)
    db.commit()
    db.refresh(event)
    return event
