from sqlmodel import SQLModel, create_engine, Session

# Defaults
DB_URL = "sqlite:///vulnerabilities.db"
engine = None

def get_engine():
    global engine
    if engine is None:
        engine = create_engine(DB_URL)
    return engine

def create_db_and_tables():
    SQLModel.metadata.create_all(get_engine())

def get_session():
    return Session(get_engine())
