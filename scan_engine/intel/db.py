from sqlmodel import SQLModel, create_engine, Session
from contextlib import contextmanager

# Defaults
DB_URL = "sqlite:///vulnerabilities.db"
engine = None

def get_engine():
    global engine
    if engine is None:
        # Optimization for SQLite and QueuePool management
        engine = create_engine(
            DB_URL,
            pool_size=20,
            max_overflow=10,
            pool_recycle=3600,
            connect_args={"check_same_thread": False} # Required for SQLite + FastAPI
        )
    return engine

def create_db_and_tables():
    # Crucial: Import all models here to register them with metadata before create_all
    from . import models
    import scan_engine.audit as audit_mod
    SQLModel.metadata.create_all(get_engine())

@contextmanager
def get_session():
    """Context manager for database sessions to prevent connection leaks."""
    session = Session(get_engine())
    try:
        yield session
    finally:
        session.close()
