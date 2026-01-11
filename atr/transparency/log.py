"""Transparency log implementation"""
import json
from typing import List, Optional, Dict, Any
from datetime import datetime
from sqlalchemy.orm import Session
from sqlalchemy import Column, Integer, String, DateTime, Text, JSON, Enum as SQLEnum
from sqlalchemy.sql import func

from atr.core.db import Base
from atr.core.models import AuditEventType
from atr.transparency.merkle import MerkleTree, hash_data


class TransparencyLogEntry(Base):
    """Transparency log entry"""
    __tablename__ = "transparency_log"
    
    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    entry_index = Column(Integer, unique=True, nullable=False, index=True)  # Sequential index
    event_type = Column(String(50), nullable=False)
    agent_name = Column(String(255), nullable=True)
    event_data = Column(JSON, nullable=False)  # Full event data
    entry_hash = Column(String(64), nullable=False, index=True)  # Hash of this entry
    tree_root_hash = Column(String(64), nullable=True, index=True)  # Root hash after this entry
    created_at = Column(DateTime, server_default=func.now(), nullable=False)
    
    def to_bytes(self) -> bytes:
        """Convert log entry to bytes for hashing"""
        data = {
            "entry_index": self.entry_index,
            "event_type": self.event_type,
            "agent_name": self.agent_name,
            "event_data": self.event_data,
            "created_at": self.created_at.isoformat() if self.created_at else None
        }
        return json.dumps(data, sort_keys=True).encode('utf-8')


class TransparencyLog:
    """Transparency log manager"""
    
    def __init__(self, db: Session):
        self.db = db
        self._checkpoint_interval = 100  # Create checkpoint every N entries
    
    def add_entry(
        self,
        event_type: AuditEventType,
        agent_name: Optional[str],
        event_data: Dict[str, Any]
    ) -> TransparencyLogEntry:
        """Add an entry to the transparency log"""
        # Get next entry index
        last_entry = self.db.query(TransparencyLogEntry).order_by(
            TransparencyLogEntry.entry_index.desc()
        ).first()
        
        entry_index = (last_entry.entry_index + 1) if last_entry else 0
        
        # Create entry
        entry = TransparencyLogEntry(
            entry_index=entry_index,
            event_type=event_type.value,
            agent_name=agent_name,
            event_data=event_data,
            created_at=datetime.utcnow()
        )
        
        # Compute entry hash
        entry_bytes = entry.to_bytes()
        entry.entry_hash = hash_data(entry_bytes)
        
        # Add to database
        self.db.add(entry)
        
        # Rebuild tree and update root hash
        all_entries = self.db.query(TransparencyLogEntry).order_by(
            TransparencyLogEntry.entry_index
        ).all()
        
        if all_entries:
            entries_bytes = [e.to_bytes() for e in all_entries]
            tree = MerkleTree(entries_bytes)
            root_hash = tree.get_root_hash()
            
            # Update root hash for this entry
            entry.tree_root_hash = root_hash
        
        self.db.commit()
        self.db.refresh(entry)
        
        return entry
    
    def get_entry(self, entry_index: int) -> Optional[TransparencyLogEntry]:
        """Get log entry by index"""
        return self.db.query(TransparencyLogEntry).filter(
            TransparencyLogEntry.entry_index == entry_index
        ).first()
    
    def get_entries(
        self,
        limit: int = 100,
        offset: int = 0,
        agent_name: Optional[str] = None,
        event_type: Optional[AuditEventType] = None
    ) -> List[TransparencyLogEntry]:
        """Get log entries with filtering"""
        query = self.db.query(TransparencyLogEntry)
        
        if agent_name:
            query = query.filter(TransparencyLogEntry.agent_name == agent_name)
        
        if event_type:
            query = query.filter(TransparencyLogEntry.event_type == event_type.value)
        
        return query.order_by(TransparencyLogEntry.entry_index.desc()).offset(offset).limit(limit).all()
    
    def get_latest_root_hash(self) -> Optional[str]:
        """Get the latest root hash"""
        latest = self.db.query(TransparencyLogEntry).order_by(
            TransparencyLogEntry.entry_index.desc()
        ).first()
        
        return latest.tree_root_hash if latest else None
    
    def generate_inclusion_proof(self, entry_index: int) -> Optional[Dict[str, Any]]:
        """Generate inclusion proof for an entry"""
        entry = self.get_entry(entry_index)
        if not entry:
            return None
        
        # Get all entries up to this one
        all_entries = self.db.query(TransparencyLogEntry).filter(
            TransparencyLogEntry.entry_index <= entry_index
        ).order_by(TransparencyLogEntry.entry_index).all()
        
        if not all_entries:
            return None
        
        # Build tree
        entries_bytes = [e.to_bytes() for e in all_entries]
        tree = MerkleTree(entries_bytes)
        
        # Find entry position in tree
        entry_pos = next(i for i, e in enumerate(all_entries) if e.entry_index == entry_index)
        
        # Generate proof
        proof = tree.generate_inclusion_proof(entry_pos)
        root_hash = tree.get_root_hash()
        
        return {
            "entry_index": entry_index,
            "entry_hash": entry.entry_hash,
            "root_hash": root_hash,
            "proof": proof,
            "tree_size": len(all_entries)
        }
    
    def verify_inclusion_proof(
        self,
        entry_index: int,
        root_hash: str,
        proof: List[str]
    ) -> bool:
        """Verify an inclusion proof"""
        entry = self.get_entry(entry_index)
        if not entry:
            return False
        
        # Get all entries up to this one
        all_entries = self.db.query(TransparencyLogEntry).filter(
            TransparencyLogEntry.entry_index <= entry_index
        ).order_by(TransparencyLogEntry.entry_index).all()
        
        if not all_entries:
            return False
        
        # Build tree
        entries_bytes = [e.to_bytes() for e in all_entries]
        tree = MerkleTree(entries_bytes)
        
        # Find entry position
        entry_pos = next(i for i, e in enumerate(all_entries) if e.entry_index == entry_index)
        
        # Verify proof
        return tree.verify_inclusion_proof(
            entries_bytes[entry_pos],
            entry_pos,
            root_hash,
            proof
        )
