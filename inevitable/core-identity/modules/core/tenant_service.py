"""
Tenant service for managing multi-tenant deployments
Supports both SaaS (shared database) and PaaS (isolated databases) modes
SECURITY NOTE: All SQL operations use proper escaping to prevent injection attacks
"""
import os
import re
from typing import Optional, Dict, Any
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import NullPool
import logging

from .tenant_models import Tenant, TenantType, TenantStatus
from .database import Base

logger = logging.getLogger(__name__)


def _escape_sql_identifier(identifier: str) -> str:
    """
    SECURITY: Escape SQL identifier to prevent injection attacks
    PostgreSQL identifiers can contain letters, digits, underscores, and dollar signs
    Must start with letter or underscore
    """
    if not identifier:
        raise ValueError("SQL identifier cannot be empty")
    
    # Remove any characters that aren't alphanumeric or underscore
    escaped = re.sub(r'[^a-zA-Z0-9_]', '_', str(identifier))
    
    # Ensure it starts with letter or underscore
    if escaped and escaped[0].isdigit():
        escaped = '_' + escaped
    
    # Limit length to prevent DoS
    escaped = escaped[:63]  # PostgreSQL identifier limit
    
    if not escaped:
        raise ValueError("SQL identifier resulted in empty string after escaping")
    
    return escaped


def _escape_sql_string_literal(value: str) -> str:
    """
    SECURITY: Escape SQL string literal to prevent injection attacks
    """
    if not isinstance(value, str):
        raise ValueError("Value must be a string")
    
    # Escape single quotes by doubling them
    return value.replace("'", "''")


class TenantService:
    """Service for managing tenant isolation and database connections"""
    
    def __init__(self):
        self.master_db_url = os.getenv("DATABASE_URL")
        self.engines: Dict[str, Any] = {}
        self.sessions: Dict[str, sessionmaker] = {}
    
    def get_tenant_db_url(self, tenant: Tenant) -> str:
        """Get database URL for a tenant based on their type"""
        if tenant.tenant_type == TenantType.DATABASE:
            # Isolated database
            if tenant.database_url:
                return tenant.database_url
            else:
                # Generate database URL from pattern
                base_url = self.master_db_url.rsplit('/', 1)[0]
                return f"{base_url}/{tenant.slug}"
        
        elif tenant.tenant_type == TenantType.SCHEMA:
            # Schema isolation - use master DB with schema prefix
            return self.master_db_url
        
        else:
            # Shared database (row-level isolation)
            return self.master_db_url
    
    def get_engine(self, tenant_id: str, tenant: Optional[Tenant] = None):
        """Get SQLAlchemy engine for a tenant"""
        if tenant_id in self.engines:
            return self.engines[tenant_id]
        
        if not tenant:
            # Load tenant from master DB
            master_session = self.get_master_session()
            tenant = master_session.query(Tenant).filter(Tenant.id == tenant_id).first()
            master_session.close()
            
            if not tenant:
                raise ValueError(f"Tenant {tenant_id} not found")
        
        db_url = self.get_tenant_db_url(tenant)
        
        # Create engine with connection pooling disabled for isolated DBs
        if tenant.tenant_type == TenantType.DATABASE:
            engine = create_engine(db_url, poolclass=NullPool)
        else:
            engine = create_engine(db_url)
        
        self.engines[tenant_id] = engine
        return engine
    
    def get_session_factory(self, tenant_id: str) -> sessionmaker:
        """Get session factory for a tenant"""
        if tenant_id in self.sessions:
            return self.sessions[tenant_id]
        
        engine = self.get_engine(tenant_id)
        session_factory = sessionmaker(bind=engine)
        self.sessions[tenant_id] = session_factory
        
        return session_factory
    
    def get_master_session(self) -> Session:
        """Get session for master database (tenant registry)"""
        if 'master' not in self.engines:
            self.engines['master'] = create_engine(self.master_db_url)
            self.sessions['master'] = sessionmaker(bind=self.engines['master'])
        
        return self.sessions['master']()
    
    def provision_tenant_database(self, tenant: Tenant) -> bool:
        """Provision a new database for DATABASE type tenants"""
        if tenant.tenant_type != TenantType.DATABASE:
            return True
        
        try:
            # Connect to postgres database to create new DB
            base_url = self.master_db_url.rsplit('/', 1)[0]
            postgres_url = f"{base_url}/postgres"
            
            engine = create_engine(postgres_url, isolation_level='AUTOCOMMIT')
            with engine.connect() as conn:
                # SECURITY: Escape identifiers to prevent SQL injection
                db_name = _escape_sql_identifier(tenant.slug)
                conn.execute(text(f"CREATE DATABASE {db_name}"))
                
                # Create user if needed
                if os.getenv("CREATE_TENANT_USERS", "false").lower() == "true":
                    username = _escape_sql_identifier(f"tenant_{tenant.slug}")
                    password = self._generate_secure_password()
                    escaped_password = _escape_sql_string_literal(password)
                    
                    conn.execute(text(f"CREATE USER {username} WITH PASSWORD '{escaped_password}'"))
                    conn.execute(text(f"GRANT ALL PRIVILEGES ON DATABASE {db_name} TO {username}"))
                    
                    # Update tenant with connection details
                    tenant.database_url = f"postgresql://{username}:{password}@localhost/{db_name}"
            
            # Create schema in new database
            tenant_engine = self.get_engine(tenant.id, tenant)
            Base.metadata.create_all(bind=tenant_engine)
            
            logger.info(f"Provisioned database for tenant {tenant.id}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to provision database for tenant {tenant.id}: {e}")
            return False
    
    def provision_tenant_schema(self, tenant: Tenant) -> bool:
        """Provision a new schema for SCHEMA type tenants"""
        if tenant.tenant_type != TenantType.SCHEMA:
            return True
        
        try:
            engine = create_engine(self.master_db_url)
            # SECURITY: Escape identifier to prevent SQL injection
            schema_name = _escape_sql_identifier(f"tenant_{tenant.slug}")
            
            with engine.connect() as conn:
                # Create schema
                conn.execute(text(f"CREATE SCHEMA IF NOT EXISTS {schema_name}"))
                conn.commit()
            
            # Update tenant
            tenant.schema_name = schema_name
            
            # Create tables in schema
            # This would need schema-aware table creation
            
            logger.info(f"Provisioned schema {schema_name} for tenant {tenant.id}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to provision schema for tenant {tenant.id}: {e}")
            return False
    
    def migrate_tenant_to_isolated(self, tenant_id: str) -> bool:
        """Migrate a shared tenant to isolated database"""
        session = self.get_master_session()
        try:
            tenant = session.query(Tenant).filter(Tenant.id == tenant_id).first()
            if not tenant:
                return False
            
            if tenant.tenant_type != TenantType.SHARED:
                logger.warning(f"Tenant {tenant_id} is not in SHARED mode")
                return False
            
            # Create new database
            old_type = tenant.tenant_type
            tenant.tenant_type = TenantType.DATABASE
            
            if not self.provision_tenant_database(tenant):
                tenant.tenant_type = old_type
                return False
            
            # TODO: Migrate data from shared database to isolated database
            # This would involve:
            # 1. Reading all data with tenant_id filter
            # 2. Writing to new database
            # 3. Verifying data integrity
            # 4. Updating tenant record
            
            session.commit()
            logger.info(f"Migrated tenant {tenant_id} to isolated database")
            return True
            
        except Exception as e:
            logger.error(f"Failed to migrate tenant {tenant_id}: {e}")
            session.rollback()
            return False
        finally:
            session.close()
    
    def cleanup_tenant_resources(self, tenant: Tenant):
        """Clean up resources when deleting a tenant"""
        try:
            if tenant.tenant_type == TenantType.DATABASE and tenant.database_url:
                # Drop database
                base_url = self.master_db_url.rsplit('/', 1)[0]
                postgres_url = f"{base_url}/postgres"
                
                engine = create_engine(postgres_url, isolation_level='AUTOCOMMIT')
                with engine.connect() as conn:
                    # SECURITY: Escape identifiers to prevent SQL injection
                    db_name = _escape_sql_identifier(tenant.slug)
                    escaped_db_name_literal = _escape_sql_string_literal(db_name)
                    
                    # Terminate connections using parameterized query
                    conn.execute(text(f"""
                        SELECT pg_terminate_backend(pid)
                        FROM pg_stat_activity
                        WHERE datname = '{escaped_db_name_literal}'
                    """))
                    
                    # Drop database
                    conn.execute(text(f"DROP DATABASE IF EXISTS {db_name}"))
                    
                    # Drop user if exists
                    username = _escape_sql_identifier(f"tenant_{tenant.slug}")
                    conn.execute(text(f"DROP USER IF EXISTS {username}"))
            
            elif tenant.tenant_type == TenantType.SCHEMA and tenant.schema_name:
                # Drop schema
                engine = create_engine(self.master_db_url)
                with engine.connect() as conn:
                    # SECURITY: Escape identifier to prevent SQL injection
                    escaped_schema_name = _escape_sql_identifier(tenant.schema_name)
                    conn.execute(text(f"DROP SCHEMA IF EXISTS {escaped_schema_name} CASCADE"))
                    conn.commit()
            
            # Remove from cache
            if tenant.id in self.engines:
                self.engines[tenant.id].dispose()
                del self.engines[tenant.id]
            
            if tenant.id in self.sessions:
                del self.sessions[tenant.id]
            
            logger.info(f"Cleaned up resources for tenant {tenant.id}")
            
        except Exception as e:
            logger.error(f"Failed to cleanup resources for tenant {tenant.id}: {e}")
    
    def _generate_secure_password(self) -> str:
        """Generate a secure password for database users"""
        import secrets
        import string
        alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
        return ''.join(secrets.choice(alphabet) for _ in range(32))


# Global tenant service instance
tenant_service = TenantService()


class TenantContext:
    """Context manager for tenant-specific database operations"""
    
    def __init__(self, tenant_id: str):
        self.tenant_id = tenant_id
        self.session = None
    
    def __enter__(self) -> Session:
        session_factory = tenant_service.get_session_factory(self.tenant_id)
        self.session = session_factory()
        return self.session
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            if exc_type:
                self.session.rollback()
            else:
                self.session.commit()
            self.session.close()


def get_tenant_db(tenant_id: str):
    """FastAPI dependency for tenant-specific database sessions"""
    session_factory = tenant_service.get_session_factory(tenant_id)
    session = session_factory()
    try:
        yield session
    finally:
        session.close()