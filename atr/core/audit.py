"""Audit logging utilities"""
import uuid
from datetime import datetime
from sqlalchemy.orm import Session
from typing import Optional, Dict, Any

from atr.core.models import AuditEvent, AuditEventType
from atr.core.config import settings


# Lazy import to avoid circular dependencies
_transparency_log = None


def _get_transparency_log(db: Session):
    """Get transparency log instance (lazy initialization)"""
    global _transparency_log
    if _transparency_log is None and settings.transparency_log_enabled:
        from atr.transparency.log import TransparencyLog
        _transparency_log = TransparencyLog(db)
    return _transparency_log


def log_audit_event(
    db: Session,
    event_type: AuditEventType,
    agent_name: Optional[str] = None,
    actor: Optional[str] = None,
    metadata: Optional[Dict[str, Any]] = None
) -> AuditEvent:
    """Create and persist an audit event (also logs to transparency log if enabled)"""
    # Create audit event
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
    
    # Also log to transparency log if enabled (v0.3 feature)
    try:
        tlog = _get_transparency_log(db)
        if tlog:
            event_data = {
                "event_id": event.id,
                "event_type": event_type.value,
                "agent_name": agent_name,
                "actor": actor,
                "metadata": metadata or {},
                "timestamp": event.timestamp.isoformat() if event.timestamp else None
            }
            tlog.add_entry(event_type, agent_name, event_data)
    except Exception:
        # Transparency log failures shouldn't break audit logging
        pass
    
    return event
