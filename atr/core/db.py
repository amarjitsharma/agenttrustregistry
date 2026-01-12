"""Database session management"""
from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker, Session
from sqlalchemy.pool import StaticPool
from typing import Generator

from atr.core.config import settings

# SQLite needs special handling for foreign keys
connect_args = {}
poolclass = None
if settings.database_url.startswith("sqlite"):
    connect_args = {"check_same_thread": False}
    poolclass = StaticPool

engine = create_engine(
    settings.database_url,
    connect_args=connect_args,
    poolclass=poolclass,
    echo=False
)

# v0.4: Optimize connection pool for non-SQLite databases
if "sqlite" not in settings.database_url:
    try:
        from atr.performance.db_optimization import optimize_connection_pool, setup_query_logging
        optimize_connection_pool(engine)
        setup_query_logging(engine)
    except Exception:
        # If optimization fails, continue with default settings
        pass

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


def get_db() -> Generator[Session, None, None]:
    """Dependency for FastAPI to get DB session"""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
