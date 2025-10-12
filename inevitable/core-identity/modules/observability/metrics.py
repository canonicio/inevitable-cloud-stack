"""
Metrics collection and monitoring for Platform Forge
"""
import time
from typing import Dict, Any
from prometheus_client import Counter, Histogram, Gauge, Info, generate_latest, CollectorRegistry
from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
import logging

logger = logging.getLogger(__name__)

# Create global registry
REGISTRY = CollectorRegistry()

# HTTP metrics
http_requests_total = Counter(
    'http_requests_total',
    'Total HTTP requests',
    ['method', 'endpoint', 'status_code', 'tenant_id'],
    registry=REGISTRY
)

http_request_duration_seconds = Histogram(
    'http_request_duration_seconds',
    'HTTP request duration in seconds',
    ['method', 'endpoint', 'tenant_id'],
    registry=REGISTRY
)

# Authentication metrics
auth_login_attempts_total = Counter(
    'auth_login_attempts_total',
    'Total login attempts',
    ['result', 'tenant_id'],
    registry=REGISTRY
)

auth_login_failures_total = Counter(
    'auth_login_failures_total',
    'Total login failures',
    ['reason', 'tenant_id'],
    registry=REGISTRY
)

mfa_challenges_total = Counter(
    'mfa_challenges_total',
    'Total MFA challenges',
    ['result', 'tenant_id'],
    registry=REGISTRY
)

# Billing metrics
billing_operations_total = Counter(
    'billing_operations_total',
    'Total billing operations',
    ['operation', 'result', 'tenant_id'],
    registry=REGISTRY
)

stripe_webhook_events_total = Counter(
    'stripe_webhook_events_total',
    'Total Stripe webhook events',
    ['event_type', 'result'],
    registry=REGISTRY
)

# Database metrics
db_connections_active = Gauge(
    'db_connections_active',
    'Active database connections',
    registry=REGISTRY
)

db_connections_idle = Gauge(
    'db_connections_idle',
    'Idle database connections',
    registry=REGISTRY
)

db_query_duration_seconds = Histogram(
    'db_query_duration_seconds',
    'Database query duration in seconds',
    ['operation', 'table'],
    registry=REGISTRY
)

# Security metrics
security_violations_total = Counter(
    'security_violations_total',
    'Total security violations',
    ['violation_type', 'severity', 'tenant_id'],
    registry=REGISTRY
)

rate_limit_exceeded_total = Counter(
    'rate_limit_exceeded_total',
    'Total rate limit exceeded events',
    ['endpoint', 'tenant_id'],
    registry=REGISTRY
)

# Application info
app_info = Info(
    'platform_forge_app_info',
    'Platform Forge application info',
    registry=REGISTRY
)

# Set application info
app_info.info({
    'version': '1.0.0',
    'name': 'Platform Forge',
    'description': 'Modular SaaS/PaaS Generator'
})


class MetricsMiddleware(BaseHTTPMiddleware):
    """Middleware to collect HTTP metrics."""
    
    def __init__(self, app, registry=None):
        super().__init__(app)
        self.registry = registry or REGISTRY
    
    async def dispatch(self, request: Request, call_next):
        """Collect metrics for each request."""
        start_time = time.time()
        
        # Extract tenant ID from validated request state (set by SecurityMiddleware)
        tenant_id = getattr(request.state, 'tenant_id', 'unknown')
        
        # Get endpoint pattern
        endpoint = self._get_endpoint_pattern(request)
        
        try:
            response = await call_next(request)
            
            # Record metrics
            duration = time.time() - start_time
            
            http_requests_total.labels(
                method=request.method,
                endpoint=endpoint,
                status_code=response.status_code,
                tenant_id=tenant_id
            ).inc()
            
            http_request_duration_seconds.labels(
                method=request.method,
                endpoint=endpoint,
                tenant_id=tenant_id
            ).observe(duration)
            
            return response
            
        except Exception as e:
            # Record error metrics
            duration = time.time() - start_time
            
            http_requests_total.labels(
                method=request.method,
                endpoint=endpoint,
                status_code=500,
                tenant_id=tenant_id
            ).inc()
            
            http_request_duration_seconds.labels(
                method=request.method,
                endpoint=endpoint,
                tenant_id=tenant_id
            ).observe(duration)
            
            raise e
    
    def _get_endpoint_pattern(self, request: Request) -> str:
        """Extract endpoint pattern from request."""
        path = request.url.path
        
        # Simple pattern matching for common endpoints
        if path.startswith('/api/auth/'):
            return '/api/auth/*'
        elif path.startswith('/api/billing/'):
            return '/api/billing/*'
        elif path.startswith('/api/admin/'):
            return '/api/admin/*'
        elif path.startswith('/webhooks/'):
            return '/webhooks/*'
        elif path == '/health':
            return '/health'
        elif path == '/metrics':
            return '/metrics'
        else:
            return path


def get_metrics_registry():
    """Get the global metrics registry."""
    return REGISTRY


def get_metrics():
    """Get metrics in Prometheus format."""
    return generate_latest(REGISTRY)


def record_auth_attempt(result: str, tenant_id: str = "unknown"):
    """Record authentication attempt."""
    auth_login_attempts_total.labels(result=result, tenant_id=tenant_id).inc()


def record_auth_failure(reason: str, tenant_id: str = "unknown"):
    """Record authentication failure."""
    auth_login_failures_total.labels(reason=reason, tenant_id=tenant_id).inc()


def record_mfa_challenge(result: str, tenant_id: str = "unknown"):
    """Record MFA challenge."""
    mfa_challenges_total.labels(result=result, tenant_id=tenant_id).inc()


def record_billing_operation(operation: str, result: str, tenant_id: str = "unknown"):
    """Record billing operation."""
    billing_operations_total.labels(
        operation=operation, result=result, tenant_id=tenant_id
    ).inc()


def record_stripe_webhook(event_type: str, result: str):
    """Record Stripe webhook event."""
    stripe_webhook_events_total.labels(event_type=event_type, result=result).inc()


def record_security_violation(violation_type: str, severity: str, tenant_id: str = "unknown"):
    """Record security violation."""
    security_violations_total.labels(
        violation_type=violation_type, severity=severity, tenant_id=tenant_id
    ).inc()


def record_rate_limit_exceeded(endpoint: str, tenant_id: str = "unknown"):
    """Record rate limit exceeded."""
    rate_limit_exceeded_total.labels(endpoint=endpoint, tenant_id=tenant_id).inc()


def update_db_connections(active: int, idle: int):
    """Update database connection metrics."""
    db_connections_active.set(active)
    db_connections_idle.set(idle)


def record_db_query_duration(operation: str, table: str, duration: float):
    """Record database query duration."""
    db_query_duration_seconds.labels(operation=operation, table=table).observe(duration)


# Alias for backward compatibility
metrics_middleware = MetricsMiddleware