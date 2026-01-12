"""Certificate Renewal Automation (v0.4)

This module provides automated certificate renewal functionality
for agents with expiring certificates.
"""
from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta
from sqlalchemy.orm import Session
from sqlalchemy import and_

from atr.core.models import Agent, AgentStatus
from atr.core.config import settings
from atr.ra.service import RegistrationAuthority


class CertificateRenewalService:
    """Service for automated certificate renewal"""
    
    def __init__(self, db: Session):
        self.db = db
        self.ra = RegistrationAuthority(db)
    
    def find_certificates_expiring_soon(
        self,
        days_ahead: int = 7
    ) -> List[Agent]:
        """
        Find agents with certificates expiring within the specified days.
        
        Args:
            days_ahead: Number of days ahead to check (default: 7)
            
        Returns:
            List of Agent objects with expiring certificates
        """
        threshold_date = datetime.utcnow() + timedelta(days=days_ahead)
        
        agents = self.db.query(Agent).filter(
            and_(
                Agent.status == AgentStatus.ACTIVE,
                Agent.expires_at <= threshold_date,
                Agent.expires_at > datetime.utcnow()  # Not already expired
            )
        ).all()
        
        return agents
    
    def find_expired_certificates(self) -> List[Agent]:
        """
        Find agents with expired certificates.
        
        Returns:
            List of Agent objects with expired certificates
        """
        agents = self.db.query(Agent).filter(
            and_(
                Agent.status == AgentStatus.ACTIVE,
                Agent.expires_at < datetime.utcnow()
            )
        ).all()
        
        return agents
    
    def renew_certificate(self, agent_name: str) -> Dict[str, Any]:
        """
        Renew a certificate for an agent.
        
        Args:
            agent_name: Agent name
            
        Returns:
            Dict with renewal result
        """
        try:
            agent = self.ra.rotate_certificate(agent_name)
            return {
                "success": True,
                "agent_name": agent_name,
                "new_fingerprint": agent.cert_fingerprint,
                "new_expires_at": agent.expires_at.isoformat(),
                "renewed_at": datetime.utcnow().isoformat()
            }
        except Exception as e:
            return {
                "success": False,
                "agent_name": agent_name,
                "error": str(e),
                "renewed_at": datetime.utcnow().isoformat()
            }
    
    def renew_expiring_certificates(
        self,
        days_ahead: int = 7,
        dry_run: bool = False
    ) -> Dict[str, Any]:
        """
        Renew all certificates expiring within the specified days.
        
        Args:
            days_ahead: Number of days ahead to check (default: 7)
            dry_run: If True, don't actually renew, just report
            
        Returns:
            Dict with renewal results
        """
        agents = self.find_certificates_expiring_soon(days_ahead)
        
        results = {
            "dry_run": dry_run,
            "checked_at": datetime.utcnow().isoformat(),
            "days_ahead": days_ahead,
            "total_found": len(agents),
            "renewed": [],
            "failed": []
        }
        
        for agent in agents:
            if dry_run:
                results["renewed"].append({
                    "agent_name": agent.agent_name,
                    "current_expires_at": agent.expires_at.isoformat(),
                    "status": "would_renew"
                })
            else:
                renewal_result = self.renew_certificate(agent.agent_name)
                if renewal_result["success"]:
                    results["renewed"].append(renewal_result)
                else:
                    results["failed"].append(renewal_result)
        
        return results


def check_and_renew_certificates(
    db: Session,
    days_ahead: int = 7,
    dry_run: bool = False
) -> Dict[str, Any]:
    """
    Convenience function to check and renew expiring certificates.
    
    Args:
        db: Database session
        days_ahead: Number of days ahead to check (default: 7)
        dry_run: If True, don't actually renew, just report
        
    Returns:
        Dict with renewal results
    """
    service = CertificateRenewalService(db)
    return service.renew_expiring_certificates(days_ahead, dry_run)
