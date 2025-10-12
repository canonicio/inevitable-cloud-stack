"""
Telemetry business logic and services
"""
import os
from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, and_

from modules.core.config import settings
from .models import TelemetryConfig, UsageMetrics
from .client import TelemetryClient
from .privacy import PrivacyEngine, PrivacyMode, ConsentManager


class TelemetryService:
    """Handle telemetry operations"""
    
    def __init__(self, db: AsyncSession):
        self.db = db
        self.consent_manager = ConsentManager()
        self._client = None
    
    async def get_config(self, tenant_id: str) -> TelemetryConfig:
        """Get telemetry configuration for tenant"""
        # Load from database or environment
        config = TelemetryConfig(
            enabled=os.getenv("TELEMETRY_ENABLED", "true").lower() == "true",
            mode=os.getenv("TELEMETRY_MODE", "callback"),
            endpoint=os.getenv("TELEMETRY_ENDPOINT"),
            api_key=os.getenv("TELEMETRY_API_KEY"),
            privacy_mode=os.getenv("TELEMETRY_PRIVACY_MODE", "standard")
        )
        
        return config
    
    async def get_collected_data_types(self, privacy_mode: str) -> List[str]:
        """Get list of data types collected in privacy mode"""
        data_types = {
            "minimal": [
                "Deployment ID",
                "Application version",
                "Event timestamps",
                "Basic error counts"
            ],
            "standard": [
                "Deployment ID",
                "Application version", 
                "Event timestamps",
                "Usage metrics (anonymized)",
                "Feature usage statistics",
                "Performance metrics",
                "Error information (no stack traces)"
            ],
            "enhanced": [
                "Hashed deployment ID",
                "Application version",
                "Aggregated usage metrics",
                "Anonymized feature usage",
                "General performance data"
            ],
            "maximum": [
                "Deployment ID only",
                "Version information",
                "Uptime statistics"
            ]
        }
        
        return data_types.get(privacy_mode, data_types["standard"])
    
    async def update_consent(self, user_id: str, purpose: str, consent: bool) -> None:
        """Update user consent for telemetry"""
        self.consent_manager.record_consent(user_id, purpose, consent)
        
        # Store in database (if implemented)
        # await self._store_consent_record(user_id, purpose, consent)
    
    async def get_consent_status(self, user_id: str) -> Dict[str, Any]:
        """Get user's consent status"""
        return {
            "user_id": user_id,
            "consents": {
                "telemetry": self.consent_manager.has_consent(user_id, "telemetry"),
                "analytics": self.consent_manager.has_consent(user_id, "analytics"),
                "error_reporting": self.consent_manager.has_consent(user_id, "error_reporting")
            },
            "last_updated": datetime.utcnow().isoformat()
        }
    
    async def get_current_metrics(self, tenant_id: str) -> UsageMetrics:
        """Get current usage metrics for tenant"""
        # Import here to avoid circular dependency
        from modules.auth.models import User
        from modules.billing.models import Subscription
        
        # Count active users (logged in within 30 days)
        active_users = await self.db.scalar(
            select(func.count(User.id))
            .where(
                and_(
                    User.tenant_id == tenant_id,
                    User.last_login >= datetime.utcnow() - timedelta(days=30)
                )
            )
        )
        
        # Count total users
        total_users = await self.db.scalar(
            select(func.count(User.id))
            .where(User.tenant_id == tenant_id)
        )
        
        # Get database size (approximate)
        db_size_query = """
        SELECT pg_database_size(current_database()) / 1024 / 1024 as size_mb
        """
        result = await self.db.execute(db_size_query)
        db_size = result.scalar() or 0
        
        # Build metrics
        metrics = UsageMetrics(
            active_users=active_users or 0,
            total_users=total_users or 0,
            database_size_mb=float(db_size),
            # These would be populated from actual tracking
            api_requests=0,
            api_errors=0,
            storage_used_mb=0,
            compute_hours=0
        )
        
        # Apply privacy filters
        config = await self.get_config(tenant_id)
        privacy_engine = PrivacyEngine(PrivacyMode(config.privacy_mode))
        filtered_metrics = privacy_engine.filter_metrics(metrics.model_dump())
        
        return UsageMetrics(**filtered_metrics)
    
    async def export_telemetry(self, tenant_id: str) -> str:
        """Export telemetry data for airgapped upload"""
        config = await self.get_config(tenant_id)
        config.mode = "export"  # Force export mode
        
        if not self._client:
            self._client = TelemetryClient(config)
        
        # Collect current metrics
        metrics = await self.get_current_metrics(tenant_id)
        await self._client.track_usage(metrics)
        
        # Export to file
        export_path = os.getenv("TELEMETRY_EXPORT_PATH", "/tmp/telemetry")
        os.makedirs(export_path, exist_ok=True)
        
        export_file = await self._client.export_telemetry(export_path)
        
        return export_file
    
    async def test_connection(self) -> Dict[str, Any]:
        """Test telemetry connection"""
        config = await self.get_config("test")
        
        if not config.endpoint:
            return {
                "status": "error",
                "message": "No telemetry endpoint configured"
            }
        
        try:
            client = TelemetryClient(config)
            result = await client.validate_license()
            
            return {
                "status": "success",
                "endpoint": config.endpoint,
                "mode": config.mode,
                "privacy_mode": config.privacy_mode,
                "license_valid": result.get("valid", False)
            }
        except Exception as e:
            return {
                "status": "error",
                "message": str(e),
                "endpoint": config.endpoint
            }


class TelemetryCollector:
    """
    Background service that collects and sends telemetry.
    This runs as a background task in the generated application.
    """
    
    def __init__(self, db_session_factory):
        self.db_session_factory = db_session_factory
        self.client = None
        self.running = False
    
    async def start(self):
        """Start telemetry collection"""
        # Use synchronous session factory
        db = self.db_session_factory()
        try:
            service = TelemetryService(db)
            config = service.get_config("default")  # Sync method, not async
            
            if not config or not config.enabled:
                return
            
            self.client = TelemetryClient(config)
            self.running = True
            
            # Track deployment start
            await self.client.track_deployment()
            
            # Start periodic collection
            import asyncio
            asyncio.create_task(self._collect_periodically())
        finally:
            db.close()
    
    async def stop(self):
        """Stop telemetry collection"""
        self.running = False
        if self.client:
            await self.client.shutdown()
    
    async def _collect_periodically(self):
        """Collect metrics periodically"""
        import asyncio
        
        while self.running:
            try:
                # Collect metrics every 5 minutes
                await asyncio.sleep(300)
                
                # Use synchronous session factory
                db = self.db_session_factory()
                try:
                    service = TelemetryService(db)
                    metrics = service.get_current_metrics("default")  # Sync method
                    
                    if self.client and metrics:
                        await self.client.track_usage(metrics)
                finally:
                    db.close()
                        
            except Exception as e:
                # Don't let telemetry errors crash the app
                import logging
                logging.error(f"Telemetry collection error: {e}")