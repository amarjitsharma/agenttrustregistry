"""Security monitoring and management routes (v0.4)"""
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from typing import Dict, Any
from datetime import timedelta

from atr.core.db import get_db
from atr.core.config import settings
from atr.security.monitoring import SecurityMonitor
from atr.performance.metrics import get_metrics

router = APIRouter(prefix="/v1", tags=["security"])


@router.get("/security/summary", response_model=Dict[str, Any])
def get_security_summary(
    hours: int = 24,
    db: Session = Depends(get_db)
):
    """
    Get security summary and statistics.
    
    Args:
        hours: Time window in hours (default: 24)
        
    Returns:
        Dict with security summary
    """
    if not settings.security_monitoring_enabled:
        raise HTTPException(
            status_code=status.HTTP_501_NOT_IMPLEMENTED,
            detail="Security monitoring is not enabled in configuration."
        )
    
    monitor = SecurityMonitor(db)
    time_window = timedelta(hours=hours)
    summary = monitor.get_security_summary(time_window)
    
    return summary


@router.get("/security/anomalies", response_model=Dict[str, Any])
def get_security_anomalies(
    hours: int = 1,
    db: Session = Depends(get_db)
):
    """
    Get detected security anomalies.
    
    Args:
        hours: Time window in hours (default: 1)
        
    Returns:
        Dict with detected anomalies
    """
    if not settings.anomaly_detection_enabled:
        raise HTTPException(
            status_code=status.HTTP_501_NOT_IMPLEMENTED,
            detail="Anomaly detection is not enabled in configuration."
        )
    
    monitor = SecurityMonitor(db)
    time_window = timedelta(hours=hours)
    anomalies = monitor.detect_anomalies(time_window)
    
    return {
        "anomalies": anomalies,
        "count": len(anomalies),
        "time_window_hours": hours,
        "generated_at": monitor.get_security_summary(time_window)["generated_at"]
    }


@router.get("/performance/metrics", response_model=Dict[str, Any])
def get_performance_metrics(
    minutes: int = 60
):
    """
    Get performance metrics summary.
    
    Args:
        minutes: Time window in minutes (default: 60)
        
    Returns:
        Dict with performance metrics
    """
    if not settings.performance_monitoring_enabled:
        raise HTTPException(
            status_code=status.HTTP_501_NOT_IMPLEMENTED,
            detail="Performance monitoring is not enabled in configuration."
        )
    
    metrics = get_metrics()
    summary = metrics.get_metrics_summary(minutes)
    
    return summary
