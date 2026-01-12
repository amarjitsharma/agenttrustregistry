"""Security Monitoring and Anomaly Detection (v0.4)

This module provides security monitoring capabilities including:
- Anomaly detection for suspicious patterns
- Security event tracking
- Alert generation
"""
from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta
from collections import defaultdict
from sqlalchemy.orm import Session

from atr.core.models import AuditEvent, AuditEventType, Agent
from atr.core.config import settings


class SecurityMonitor:
    """Security monitoring and anomaly detection"""
    
    def __init__(self, db: Session):
        self.db = db
        self.alert_thresholds = {
            "failed_verifications_per_hour": 100,
            "registrations_per_domain_per_hour": 20,
            "rotations_per_agent_per_day": 5,
            "revocations_per_hour": 50,
        }
    
    def detect_anomalies(
        self,
        time_window: timedelta = timedelta(hours=1)
    ) -> List[Dict[str, Any]]:
        """
        Detect security anomalies in the system.
        
        Args:
            time_window: Time window to analyze
            
        Returns:
            List of detected anomalies
        """
        if not settings.anomaly_detection_enabled:
            return []
        
        anomalies = []
        cutoff_time = datetime.utcnow() - time_window
        
        # Check for excessive failed verifications
        failed_verifies = self.db.query(AuditEvent).filter(
            AuditEvent.event_type == AuditEventType.VERIFY,
            AuditEvent.timestamp >= cutoff_time,
            AuditEvent.event_metadata.contains({"result": "not_found"})
        ).count()
        
        if failed_verifies > self.alert_thresholds["failed_verifications_per_hour"]:
            anomalies.append({
                "type": "excessive_failed_verifications",
                "severity": "high",
                "count": failed_verifies,
                "threshold": self.alert_thresholds["failed_verifications_per_hour"],
                "message": f"Detected {failed_verifies} failed verifications in the last hour"
            })
        
        # Check for excessive registrations per domain
        recent_registrations = self.db.query(AuditEvent).filter(
            AuditEvent.event_type == AuditEventType.REGISTER,
            AuditEvent.timestamp >= cutoff_time
        ).all()
        
        domain_counts = defaultdict(int)
        for event in recent_registrations:
            if event.agent_name:
                # Extract domain from agent name
                parts = event.agent_name.split('.')
                if len(parts) > 1:
                    domain = '.'.join(parts[-2:])  # Get last two parts as domain
                    domain_counts[domain] += 1
        
        for domain, count in domain_counts.items():
            if count > self.alert_thresholds["registrations_per_domain_per_hour"]:
                anomalies.append({
                    "type": "excessive_registrations_per_domain",
                    "severity": "medium",
                    "domain": domain,
                    "count": count,
                    "threshold": self.alert_thresholds["registrations_per_domain_per_hour"],
                    "message": f"Domain {domain} has {count} registrations in the last hour"
                })
        
        # Check for excessive rotations per agent
        recent_rotations = self.db.query(AuditEvent).filter(
            AuditEvent.event_type == AuditEventType.ROTATE,
            AuditEvent.timestamp >= cutoff_time
        ).all()
        
        agent_rotation_counts = defaultdict(int)
        for event in recent_rotations:
            if event.agent_name:
                agent_rotation_counts[event.agent_name] += 1
        
        for agent_name, count in agent_rotation_counts.items():
            if count > self.alert_thresholds["rotations_per_agent_per_day"]:
                anomalies.append({
                    "type": "excessive_rotations_per_agent",
                    "severity": "medium",
                    "agent_name": agent_name,
                    "count": count,
                    "threshold": self.alert_thresholds["rotations_per_agent_per_day"],
                    "message": f"Agent {agent_name} has {count} rotations in the last hour"
                })
        
        # Check for excessive revocations
        recent_revocations = self.db.query(AuditEvent).filter(
            AuditEvent.event_type == AuditEventType.REVOKE,
            AuditEvent.timestamp >= cutoff_time
        ).count()
        
        if recent_revocations > self.alert_thresholds["revocations_per_hour"]:
            anomalies.append({
                "type": "excessive_revocations",
                "severity": "high",
                "count": recent_revocations,
                "threshold": self.alert_thresholds["revocations_per_hour"],
                "message": f"Detected {recent_revocations} revocations in the last hour"
            })
        
        return anomalies
    
    def get_security_summary(
        self,
        time_window: timedelta = timedelta(hours=24)
    ) -> Dict[str, Any]:
        """
        Get security summary for the specified time window.
        
        Args:
            time_window: Time window to analyze
            
        Returns:
            Dict with security summary statistics
        """
        cutoff_time = datetime.utcnow() - time_window
        
        # Count events by type
        event_counts = {}
        for event_type in AuditEventType:
            count = self.db.query(AuditEvent).filter(
                AuditEvent.event_type == event_type,
                AuditEvent.timestamp >= cutoff_time
            ).count()
            event_counts[event_type.value] = count
        
        # Count active vs revoked agents
        active_agents = self.db.query(Agent).filter(
            Agent.status == "active"
        ).count()
        revoked_agents = self.db.query(Agent).filter(
            Agent.status == "revoked"
        ).count()
        
        # Get recent anomalies
        anomalies = self.detect_anomalies(time_window=timedelta(hours=1))
        
        return {
            "time_window_hours": time_window.total_seconds() / 3600,
            "event_counts": event_counts,
            "agent_counts": {
                "active": active_agents,
                "revoked": revoked_agents,
                "total": active_agents + revoked_agents
            },
            "anomalies_detected": len(anomalies),
            "anomalies": anomalies,
            "generated_at": datetime.utcnow().isoformat()
        }
