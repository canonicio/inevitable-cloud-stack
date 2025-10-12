"""
Core FastAPI application factory for Platform Forge
"""
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from prometheus_client import make_asgi_app
import os
import logging
from typing import Optional

def create_app(
    title: str = "Platform Forge API",
    version: str = "0.1.0",
    enable_multitenancy: bool = True,
    modules: Optional[list] = None
) -> FastAPI:
    """
    Application factory to create FastAPI app with selected modules
    
    Args:
        title: API title
        version: API version
        enable_multitenancy: Whether to enable multi-tenant middleware
        modules: List of module names to include
    """
    app = FastAPI(
        title=title,
        version=version,
        docs_url="/api/docs" if os.getenv("DEBUG", "false").lower() == "true" else None,
        redoc_url="/api/redoc" if os.getenv("DEBUG", "false").lower() == "true" else None
    )
    
    # Configure CORS
    app.add_middleware(
        CORSMiddleware,
        allow_origins=os.getenv("CORS_ORIGINS", "*").split(","),
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    
    # Security middleware
    if os.getenv("ALLOWED_HOSTS"):
        app.add_middleware(
            TrustedHostMiddleware,
            allowed_hosts=os.getenv("ALLOWED_HOSTS").split(",")
        )
    
    # Security Headers middleware (LOW-002 FIX)
    from modules.core.security_headers import SecurityHeadersMiddleware, get_production_security_headers, get_development_security_headers
    
    # Choose headers based on environment
    if os.getenv("DEBUG", "false").lower() == "true":
        security_headers = get_development_security_headers()
    else:
        security_headers = get_production_security_headers()
    
    app.add_middleware(SecurityHeadersMiddleware, config=security_headers)
    
    # CSRF Protection middleware
    from modules.core.csrf_protection import CSRFMiddleware
    app.add_middleware(CSRFMiddleware)
    
    # HIGH-006 FIX: Add Redis-backed distributed rate limiting middleware
    from modules.core.middleware import RateLimitingMiddleware
    import redis.asyncio as redis
    
    # Initialize Redis client for rate limiting
    redis_client = None
    redis_url = os.getenv("REDIS_URL")
    if redis_url:
        try:
            redis_client = redis.from_url(redis_url, decode_responses=True)
            logger = logging.getLogger(__name__)
            logger.info("Redis rate limiting enabled")
        except Exception as e:
            logger = logging.getLogger(__name__)
            logger.warning(f"Redis connection failed, using memory fallback: {e}")
    
    app.add_middleware(RateLimitingMiddleware, redis_client=redis_client)
    
    # RISK-M002 FIX: Add distributed DDoS protection middleware
    from modules.core.ddos_protection import DDoSProtectionMiddleware
    
    # Initialize synchronous Redis client for DDoS protection
    ddos_redis_client = None
    if redis_url:
        try:
            import redis
            ddos_redis_client = redis.from_url(redis_url, decode_responses=True)
            logger = logging.getLogger(__name__)
            logger.info("DDoS protection Redis client initialized")
        except Exception as e:
            logger = logging.getLogger(__name__)
            logger.warning(f"DDoS protection Redis connection failed, using fallback: {e}")
    
    app.add_middleware(DDoSProtectionMiddleware, redis_url=redis_url, db_session_factory=None)
    
    # Tenant isolation middleware (replaces old multi-tenant middleware)
    if enable_multitenancy:
        from modules.core.tenant_isolation import TenantIsolationMiddleware
        app.add_middleware(TenantIsolationMiddleware)
    
    # CRITICAL FIX: Add comprehensive security headers middleware
    from modules.core.security_headers_middleware import SecurityHeadersMiddleware
    from modules.core.config import settings
    app.add_middleware(
        SecurityHeadersMiddleware,
        strict_mode=(settings.ENVIRONMENT == "production")
    )
    
    # Health check endpoints
    @app.get("/health")
    async def health_check():
        if "observability" in modules:
            from modules.observability.health import health_check
            return await health_check()
        return {"status": "healthy", "version": version}
    
    @app.get("/health/ready")
    async def readiness_check():
        if "observability" in modules:
            from modules.observability.health import readiness_check
            return await readiness_check()
        return {"status": "ready", "version": version}
    
    @app.get("/health/live")
    async def liveness_check():
        if "observability" in modules:
            from modules.observability.health import liveness_check
            return await liveness_check()
        return {"status": "alive", "version": version}
    
    # Add observability middleware
    if "observability" in modules:
        from modules.observability.metrics import MetricsMiddleware
        from modules.observability.logging import setup_logging
        
        # Set up logging
        setup_logging(
            log_level=os.getenv("LOG_LEVEL", "INFO"),
            log_format=os.getenv("LOG_FORMAT", "json")
        )
        
        # Add metrics middleware
        app.add_middleware(MetricsMiddleware)
    
    # Add analytics tracking middleware
    if "analytics" in modules:
        from modules.analytics.tracker import ActivityTrackingMiddleware, activity_tracker
        from modules.core.database import get_db_session_factory
        
        # Initialize activity tracker
        activity_tracker.init(get_db_session_factory())
        
        # Add tracking middleware
        app.add_middleware(ActivityTrackingMiddleware)
    
    # Mount Prometheus metrics
    metrics_app = make_asgi_app()
    app.mount("/metrics", metrics_app)
    
    # Include module routers
    if modules:
        # Auth module
        if "auth" in modules:
            from modules.auth.routes import router as auth_router
            app.include_router(auth_router, prefix="/api/auth", tags=["auth"])
        
        # Admin module (enhanced with dynamic CRUD)
        if "admin" in modules:
            from modules.admin import init_admin_routes
            admin_router = init_admin_routes(modules)
            app.include_router(admin_router, tags=["admin"])
        
        # Billing module
        if "billing" in modules:
            from modules.billing.routes import router as billing_router
            app.include_router(billing_router, prefix="/api/billing", tags=["billing"])
            
            # Register Stripe webhooks
            from modules.billing.stripe_webhooks import router as webhook_router
            app.include_router(webhook_router, prefix="/webhooks", tags=["webhooks"])
        
        # MCP Auth module (with license validation)
        if "mcp_auth" in modules:
            from modules.mcp_auth.routes import router as mcp_auth_router
            from modules.mcp_auth.license_routes import router as license_router
            from modules.mcp_auth.license_middleware import LicenseEnforcementMiddleware, UsageLimitMiddleware
            
            app.include_router(mcp_auth_router, prefix="/api/mcp", tags=["mcp-auth"])
            app.include_router(license_router, prefix="/api", tags=["license"])
            
            # Add license enforcement middleware
            app.add_middleware(LicenseEnforcementMiddleware)
            app.add_middleware(UsageLimitMiddleware)
        
        # Privacy module
        if "privacy" in modules:
            from modules.privacy.routes import router as privacy_router
            app.include_router(privacy_router, tags=["privacy"])
        
        # Telemetry module
        if "telemetry" in modules:
            from modules.telemetry.routes import router as telemetry_router
            app.include_router(telemetry_router, tags=["telemetry"])
        
        # Waitlist module
        if "waitlist" in modules:
            from modules.waitlist.routes import router as waitlist_router
            app.include_router(waitlist_router, prefix="/api", tags=["waitlist"])
        
        # White-label module
        if "whitelabel" in modules:
            from modules.whitelabel.routes import router as whitelabel_router
            app.include_router(whitelabel_router, tags=["whitelabel"])
        
        # Advanced security module
        if "security_advanced" in modules:
            from modules.security_advanced.routes import router as security_advanced_router
            app.include_router(security_advanced_router, tags=["security-advanced"])
        
        # Enterprise SSO module
        if "enterprise_sso" in modules:
            from modules.enterprise_sso.routes import router as enterprise_sso_router
            app.include_router(enterprise_sso_router, tags=["enterprise-sso"])
        
        # Advanced Billing module
        if "billing_advanced" in modules:
            from modules.billing_advanced.routes import router as billing_advanced_router
            app.include_router(billing_advanced_router, tags=["billing-advanced"])
        
        # Hybrid Deployment module
        if "hybrid_deployment" in modules:
            from modules.hybrid_deployment.routes import router as hybrid_deployment_router
            app.include_router(hybrid_deployment_router, tags=["hybrid-deployment"])
        
        # Marketplace module
        if "marketplace" in modules:
            from modules.marketplace.routes import router as marketplace_router
            app.include_router(marketplace_router, tags=["marketplace"])
        
        # Edge Deployment module
        if "edge_deployment" in modules:
            from modules.edge_deployment.routes import router as edge_deployment_router
            app.include_router(edge_deployment_router, tags=["edge-deployment"])
        
        # Performance module
        if "performance" in modules:
            from modules.performance.routes import router as performance_router
            app.include_router(performance_router, tags=["performance"])
        
        # Web3 Authentication module
        if "web3_auth" in modules:
            from modules.web3_auth.routes import router as web3_auth_router
            app.include_router(web3_auth_router, prefix="/api/web3", tags=["web3-auth"])
        
        # Analytics module
        if "analytics" in modules:
            from modules.analytics.routes import router as analytics_router
            app.include_router(analytics_router, prefix="/api/analytics", tags=["analytics"])
        
        # Web3 Billing module
        if "web3_billing" in modules:
            from modules.web3_billing.routes import router as web3_billing_router
            app.include_router(web3_billing_router, prefix="/api", tags=["web3-billing"])
        
        # Referral System module
        if "referral_system" in modules:
            from modules.referral_system.routes import router as referral_router, init_components
            from modules.core.database import get_db_session_factory

            # Initialize referral system components
            db_factory = get_db_session_factory()

            # Initialize payment processors if billing is enabled
            payment_processors = {}
            if "billing" in modules:
                # Use billing module's payment processors
                from modules.billing.stripe_service import stripe_service
                payment_processors = {
                    "stripe": stripe_service
                }

            init_components(db_factory, payment_processors)
            app.include_router(referral_router, tags=["referral"])

        # PRISM Intelligence module
        if "prism" in modules:
            from modules.prism.routes import router as prism_router
            app.include_router(prism_router, tags=["prism"])
    
    # Startup event
    @app.on_event("startup")
    async def startup_event():
        # Initialize database
        from modules.core.database import init_db
        init_db()
        
        # Log configuration
        import logging
        logger = logging.getLogger(__name__)
        logger.info(f"Starting {title} v{version}")
        logger.info(f"Modules loaded: {modules}")
        logger.info(f"Multi-tenancy: {'enabled' if enable_multitenancy else 'disabled'}")
        
        # Initialize telemetry if enabled
        # TODO: Fix async/sync mismatch in telemetry service
        # Temporarily disabled to allow app to start
        # if "telemetry" in modules:
        #     from modules.telemetry.services import TelemetryCollector
        #     from modules.core.database import get_db_session_factory
        #     
        #     # Start telemetry collector
        #     collector = TelemetryCollector(get_db_session_factory())
        #     await collector.start()
        #     
        #     # Store collector for shutdown
        #     app.state.telemetry_collector = collector
    
    # Shutdown event
    @app.on_event("shutdown")
    async def shutdown_event():
        # Shutdown telemetry if running
        if hasattr(app.state, "telemetry_collector"):
            await app.state.telemetry_collector.stop()
    
    return app