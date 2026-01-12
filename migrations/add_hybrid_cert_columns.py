"""
Database migration script: Add hybrid certificate architecture columns (v0.4)

This script adds support for dual certificates (private + public) to the agents table.
Run this script to update existing databases.

Usage:
    python migrations/add_hybrid_cert_columns.py
"""
import sqlite3
import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from atr.core.config import settings
from atr.core.db import engine, Base
from sqlalchemy import text


def migrate_database():
    """Add hybrid certificate columns to agents table"""
    
    # Check if using SQLite
    if settings.database_url.startswith("sqlite"):
        # SQLite doesn't support ALTER TABLE ADD COLUMN with constraints well
        # We'll use a more compatible approach
        db_path = settings.database_url.replace("sqlite:///", "")
        if db_path == ":memory:":
            print("⚠️  In-memory database detected. Migration not applicable.")
            return
        
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Check if columns already exist
        cursor.execute("PRAGMA table_info(agents)")
        columns = [row[1] for row in cursor.fetchall()]
        
        new_columns = [
            ("cert_type", "TEXT DEFAULT 'private'"),
            ("public_cert_fingerprint", "TEXT"),
            ("public_cert_pem", "TEXT"),
            ("public_cert_serial_number", "TEXT"),
            ("public_cert_issued_at", "DATETIME"),
            ("public_cert_expires_at", "DATETIME"),
            ("public_cert_issuer", "TEXT"),
        ]
        
        for col_name, col_def in new_columns:
            if col_name not in columns:
                try:
                    cursor.execute(f"ALTER TABLE agents ADD COLUMN {col_name} {col_def}")
                    print(f"✅ Added column: {col_name}")
                except sqlite3.OperationalError as e:
                    print(f"⚠️  Error adding column {col_name}: {e}")
            else:
                print(f"⏭️  Column {col_name} already exists, skipping")
        
        conn.commit()
        conn.close()
        print("✅ Migration completed for SQLite")
        
    else:
        # For PostgreSQL and other databases, use SQLAlchemy
        with engine.connect() as conn:
            # Check if columns exist
            result = conn.execute(text("""
                SELECT column_name 
                FROM information_schema.columns 
                WHERE table_name = 'agents'
            """))
            existing_columns = [row[0] for row in result]
            
            new_columns = [
                ("cert_type", "VARCHAR(20) DEFAULT 'private'"),
                ("public_cert_fingerprint", "VARCHAR(64)"),
                ("public_cert_pem", "TEXT"),
                ("public_cert_serial_number", "VARCHAR(64)"),
                ("public_cert_issued_at", "TIMESTAMP"),
                ("public_cert_expires_at", "TIMESTAMP"),
                ("public_cert_issuer", "VARCHAR(255)"),
            ]
            
            for col_name, col_def in new_columns:
                if col_name not in existing_columns:
                    try:
                        conn.execute(text(f"ALTER TABLE agents ADD COLUMN {col_name} {col_def}"))
                        conn.commit()
                        print(f"✅ Added column: {col_name}")
                    except Exception as e:
                        print(f"⚠️  Error adding column {col_name}: {e}")
                else:
                    print(f"⏭️  Column {col_name} already exists, skipping")
        
        print("✅ Migration completed for PostgreSQL/other databases")


if __name__ == "__main__":
    print("🔄 Starting database migration: Hybrid Certificate Architecture (v0.4)")
    print(f"📊 Database: {settings.database_url}")
    print("")
    
    try:
        migrate_database()
        print("")
        print("🎉 Migration completed successfully!")
    except Exception as e:
        print(f"❌ Migration failed: {e}")
        sys.exit(1)
