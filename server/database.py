"""Database configuration for the backup service.

This module defines the SQLAlchemy engine and session factory used to access
the relational database.  The database URL can be configured via the
``DATABASE_URL`` environment variable.  When using SQLite the database will
be stored on disk in the working directory.  For production deployments a
server like PostgreSQL should be used.
"""

from __future__ import annotations

import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session


DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./backup.db")


# Determine whether to use check_same_thread for SQLite
if DATABASE_URL.startswith("sqlite"):
    engine = create_engine(
        DATABASE_URL, connect_args={"check_same_thread": False}
    )
else:
    engine = create_engine(DATABASE_URL)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def get_db() -> Session:
    """Yield a new database session and ensure it is closed afterwards."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()