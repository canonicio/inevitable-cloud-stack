"""
Core database configuration and base models for Platform Forge
"""
from sqlalchemy import create_engine, Column, String, DateTime, Boolean, Integer
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.sql import func
from typing import Optional
import os
from contextlib import contextmanager

# Database configuration - NO DEFAULT CREDENTIALS FOR SECURITY
# Addresses HIGH-005: Weak Default Database Credentials
DATABASE_URL = os.getenv("DATABASE_URL")
if not DATABASE_URL:
    raise ValueError(
        "DATABASE_URL environment variable is required and must be set. "
        "Example: postgresql://username:secure_password@localhost:5432/dbname"
    )

# Validate database URL doesn't contain weak passwords
if "password" in DATABASE_URL.lower() and any(
    weak_pass in DATABASE_URL.lower() 
    for weak_pass in ["password", "123456", "admin", "root", "test"]
):
    import logging
    logging.getLogger(__name__).critical(
        "SECURITY WARNING: Database URL appears to contain a weak password. "
        "Please use a strong, randomly generated password."
    )

# Create engine
engine = create_engine(DATABASE_URL, pool_pre_ping=True)

# Create session factory
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Create base class for models
Base = declarative_base()


class TimestampMixin:
    """Mixin to add created_at and updated_at timestamps to models"""
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(DateTime(timezone=True), onupdate=func.now(), server_default=func.now(), nullable=False)


class TenantMixin:
    """Mixin to add tenant_id for multi-tenant support"""
    tenant_id = Column(String(50), nullable=True, index=True)


@contextmanager
def get_db() -> Session:
    """Dependency to get database session"""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


async def get_async_db():
    """Async dependency for FastAPI routes"""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db():
    """Initialize database tables"""
    Base.metadata.create_all(bind=engine)


def drop_db():
    """Drop all database tables"""
    Base.metadata.drop_all(bind=engine)


def get_db_session_factory():
    """Get the session factory for advanced usage"""
    return SessionLocal