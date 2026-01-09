"""Health check routes"""
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import text

from atr.core.db import get_db

router = APIRouter(tags=["health"])


@router.get("/healthz")
def healthz():
    """Basic health check (no DB access)"""
    return {"status": "ok"}


@router.get("/readyz")
def readyz(db: Session = Depends(get_db)):
    """Readiness check (includes DB connectivity)"""
    try:
        # Simple query to check DB connectivity
        db.execute(text("SELECT 1"))
        return {"status": "ready", "database": "connected"}
    except Exception as e:
        return {"status": "not_ready", "database": "disconnected", "error": str(e)}, 503
