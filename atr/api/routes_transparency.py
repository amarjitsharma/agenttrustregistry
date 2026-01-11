"""Transparency log routes"""
from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.orm import Session
from typing import Optional

from atr.core.db import get_db
from atr.core.models import AuditEventType
from atr.core.schemas import (
    LogEntryResponse,
    LogEntryListResponse,
    InclusionProofResponse
)
from atr.transparency.log import TransparencyLog

router = APIRouter(prefix="/v1/log", tags=["transparency"])


def get_transparency_log(db: Session = Depends(get_db)) -> TransparencyLog:
    """Get transparency log instance"""
    return TransparencyLog(db)


@router.get("/entries", response_model=LogEntryListResponse)
def list_log_entries(
    db: Session = Depends(get_db),
    limit: int = Query(default=100, ge=1, le=1000, description="Maximum number of results"),
    offset: int = Query(default=0, ge=0, description="Pagination offset"),
    agent_name: Optional[str] = Query(default=None, description="Filter by agent name"),
    event_type: Optional[AuditEventType] = Query(default=None, description="Filter by event type"),
):
    """List transparency log entries"""
    tlog = TransparencyLog(db)
    
    entries = tlog.get_entries(limit=limit, offset=offset, agent_name=agent_name, event_type=event_type)
    
    # Get total count
    total = len(tlog.get_entries(limit=10000, offset=0, agent_name=agent_name, event_type=event_type))
    
    entry_list = [
        LogEntryResponse(
            entry_index=entry.entry_index,
            event_type=entry.event_type,
            agent_name=entry.agent_name,
            event_data=entry.event_data,
            entry_hash=entry.entry_hash,
            tree_root_hash=entry.tree_root_hash,
            created_at=entry.created_at
        )
        for entry in entries
    ]
    
    latest_root_hash = tlog.get_latest_root_hash()
    
    return LogEntryListResponse(
        entries=entry_list,
        total=total,
        limit=limit,
        offset=offset,
        latest_root_hash=latest_root_hash
    )


@router.get("/entries/{entry_index}", response_model=LogEntryResponse)
def get_log_entry(entry_index: int, db: Session = Depends(get_db)):
    """Get a specific log entry"""
    tlog = TransparencyLog(db)
    entry = tlog.get_entry(entry_index)
    
    if not entry:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Log entry {entry_index} not found"
        )
    
    return LogEntryResponse(
        entry_index=entry.entry_index,
        event_type=entry.event_type,
        agent_name=entry.agent_name,
        event_data=entry.event_data,
        entry_hash=entry.entry_hash,
        tree_root_hash=entry.tree_root_hash,
        created_at=entry.created_at
    )


@router.get("/entries/{entry_index}/proof", response_model=InclusionProofResponse)
def get_inclusion_proof(entry_index: int, db: Session = Depends(get_db)):
    """Get inclusion proof for a log entry"""
    tlog = TransparencyLog(db)
    proof_data = tlog.generate_inclusion_proof(entry_index)
    
    if not proof_data:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Could not generate proof for entry {entry_index}"
        )
    
    # Verify the proof
    verified = tlog.verify_inclusion_proof(
        entry_index,
        proof_data["root_hash"],
        proof_data["proof"]
    )
    
    return InclusionProofResponse(
        entry_index=proof_data["entry_index"],
        entry_hash=proof_data["entry_hash"],
        root_hash=proof_data["root_hash"],
        proof=proof_data["proof"],
        tree_size=proof_data["tree_size"],
        verified=verified
    )


@router.get("/root", response_model=dict)
def get_latest_root(db: Session = Depends(get_db)):
    """Get latest transparency log root hash"""
    tlog = TransparencyLog(db)
    root_hash = tlog.get_latest_root_hash()
    
    if not root_hash:
        return {"root_hash": None, "message": "No entries in log yet"}
    
    return {"root_hash": root_hash}
