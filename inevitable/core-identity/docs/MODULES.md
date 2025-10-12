# Platform Forge Modules Documentation

## Overview

Platform Forge uses a modular architecture where each module provides specific functionality that can be enabled or disabled based on application requirements. Modules are composable and work together to create a complete application.

## Core Modules

### Core Module (`core/`)
**Always Required** - Provides foundational functionality for all applications.

**Features:**
- Database setup and migrations with Alembic
- FastAPI application factory with security middleware
- Tenant isolation and multi-tenancy support
- Base models with TenantMixin and TimestampMixin
- Security utilities (encryption, path sanitization, input validation)
- CSRF protection with double-submit cookies
- Response filtering and sanitization
- Configuration management with secure secrets

**Key Components:**
- `app.py` - FastAPI application factory
- `database.py` - SQLAlchemy database setup
- `security.py` - Security utilities and encryption
- `tenant_isolation.py` - Multi-tenant middleware
- `validators.py` - Input validation utilities
- `middleware.py` - Security and logging middleware

### Authentication Module (`auth/`)
User authentication, authorization, and session management.

**Features:**
- JWT-based authentication with refresh tokens
- Multi-factor authentication (TOTP, Email, SMS)
- Role-based access control (RBAC)
- Password policies and secure storage (Argon2id)
- Rate limiting for auth endpoints
- Session management and invalidation
- OAuth2 provider support (optional)
- Account lockout and brute force protection

**Key Components:**
- `routes.py` - Auth endpoints (login, register, refresh)
- `service.py` - Authentication business logic
- `mfa_providers.py` - MFA implementation
- `rbac.py` - Role and permission management
- `rate_limit.py` - Redis-backed rate limiting
- `dependencies.py` - FastAPI auth dependencies

### Admin Module (`admin/`)
Administrative functionality and management interface.

**Features:**
- Admin dashboard with MFA requirement
- Comprehensive audit logging
- User and tenant management
- System configuration interface
- Real-time monitoring dashboard
- Bulk operations support
- Export/import functionality
- Admin-specific rate limiting

**Key Components:**
- `routes.py` - Admin API endpoints
- `mfa.py` - Admin-specific MFA enforcement
- `audit_logs.py` - Audit trail implementation
- `models.py` - Admin-specific data models
- `middleware/rate_limit.py` - Admin rate limiting

### Billing Module (`billing/`)
Payment processing and subscription management.

**Features:**
- Stripe integration with SCA support
- Subscription lifecycle management
- Usage-based billing support
- Invoice generation and management
- Payment method management
- Webhook processing with deduplication
- Dunning management
- Revenue recognition
- Tax calculation support

**Key Components:**
- `stripe_service.py` - Stripe API integration
- `stripe_webhooks.py` - Webhook handlers
- `webhook_dedup.py` - Deduplication logic
- `models.py` - Billing data models
- `routes.py` - Billing API endpoints

### Observability Module (`observability/`)
Monitoring, metrics, and logging infrastructure.

**Features:**
- Prometheus metrics collection
- Grafana dashboards
- Structured JSON logging
- Health check endpoints
- Custom metric registration
- Distributed tracing support
- Performance monitoring
- Alert configuration

**Key Components:**
- `metrics.py` - Prometheus metric collectors
- `logging.py` - Structured logging setup
- `health.py` - Health check implementation
- `prometheus/` - Prometheus configuration
- `grafana/` - Dashboard definitions

### Privacy Module (`privacy/`)
GDPR compliance and privacy management.

**Features:**
- Consent management system
- Data export functionality
- Right to deletion (RTBF)
- Data anonymization
- Privacy policy versioning
- Cookie consent management
- Data retention policies
- Cross-border data transfer controls

**Key Components:**
- `consent_manager.py` - Consent tracking
- `data_requests.py` - GDPR request handling
- `anonymization.py` - Data anonymization
- `models.py` - Privacy data models
- `routes.py` - Privacy API endpoints

## Enterprise Modules

### MCP Auth Module (`mcp_auth/`)
Model Context Protocol authentication for AI integration.

**Features:**
- Enterprise MCP authentication
- Policy-based access control
- Token management for AI models
- Usage tracking and limits
- Audit logging for AI requests
- Rate limiting per model
- Cost allocation tracking

**Key Components:**
- `auth.py` - MCP authentication logic
- `policy_engine.py` - Policy evaluation
- `models.py` - MCP data models
- `routes.py` - MCP API endpoints

### Telemetry Module (`telemetry/`)
Application analytics and usage tracking.

**Features:**
- Privacy-preserving analytics
- Real-time event tracking
- Custom metrics collection
- User behavior analytics
- Performance tracking
- Conversion funnel analysis
- A/B testing support
- Data export capabilities

**See detailed documentation:** [telemetry/README.md](../modules/telemetry/README.md)

### Whitelabel Module (`whitelabel/`)
Multi-tenant branding and customization.

**Features:**
- Dynamic theme customization
- Multi-tenant branding
- Custom domain mapping
- Email template customization
- API documentation branding
- Mobile app whitelabeling
- Brand asset management
- Reseller portal

**See detailed documentation:** [whitelabel/README.md](../modules/whitelabel/README.md)

### Security Advanced Module (`security_advanced/`)
Enterprise security features and zero-trust architecture.

**Features:**
- Zero-trust security mesh
- Mutual TLS (mTLS)
- Advanced threat detection
- Vulnerability scanning
- HSM integration
- Security policy engine
- Certificate management
- Secrets management

**See detailed documentation:** [security_advanced/README.md](../modules/security_advanced/README.md)

### Billing Advanced Module (`billing_advanced/`)
Advanced billing and revenue management.

**Features:**
- Multi-provider payment processing (Stripe, PayPal, Square)
- Usage-based billing with metering
- Dunning management with retry logic
- Tax engine with global support
- Revenue recognition and reporting
- Subscription lifecycle automation
- Invoice customization
- Payment orchestration

**Key Components:**
- `payment_processor.py` - Multi-provider abstraction
- `usage_billing.py` - Usage metering and billing
- `tax_engine.py` - Tax calculation engine
- `dunning.py` - Failed payment recovery
- `revenue.py` - Revenue recognition
- `subscription_manager.py` - Advanced subscription logic

### Enterprise SSO Module (`enterprise_sso/`)
Single Sign-On and identity federation.

**Features:**
- SAML 2.0 support
- OpenID Connect (OIDC)
- LDAP/Active Directory integration
- SCIM provisioning
- Session management
- Attribute mapping
- Multi-IdP support
- Just-In-Time (JIT) provisioning

**Key Components:**
- `saml.py` - SAML implementation
- `oidc.py` - OpenID Connect provider
- `ldap.py` - LDAP integration
- `provisioning.py` - SCIM support
- `session.py` - SSO session management

### Performance Module (`performance/`)
Performance optimization and monitoring.

**Features:**
- API response optimization
- Database query optimization
- Caching strategies (Redis, CDN)
- Auto-scaling policies
- Resource management
- Performance monitoring
- Load balancing configuration
- Circuit breaker patterns

**Key Components:**
- `cache_manager.py` - Multi-layer caching
- `query_optimizer.py` - Database optimization
- `api_optimizer.py` - API performance
- `auto_scaler.py` - Scaling policies
- `cdn_manager.py` - CDN integration

### Marketplace Module (`marketplace/`)
Third-party extensions and integrations.

**Features:**
- Extension marketplace
- Plugin management
- Developer portal
- Revenue sharing
- Version management
- Security scanning
- Automated testing
- License management

**Key Components:**
- `extension_manager.py` - Extension lifecycle
- `installer.py` - Safe installation
- `validator.py` - Security validation
- `monetization.py` - Revenue sharing
- `publisher.py` - Developer tools

### Edge Deployment Module (`edge_deployment/`)
Edge computing and IoT support.

**Features:**
- Edge runtime management
- Device provisioning
- OTA updates
- Offline operation
- Data synchronization
- IoT protocol support (MQTT, CoAP)
- Edge analytics
- Security at the edge

**Key Components:**
- `edge_runtime.py` - Edge execution environment
- `device_manager.py` - Device lifecycle
- `ota_updater.py` - Update management
- `sync_engine.py` - Data synchronization
- `iot_protocols.py` - Protocol handlers

### Hybrid Deployment Module (`hybrid_deployment/`)
Multi-cloud and hybrid cloud management.

**Features:**
- Multi-cloud orchestration
- Workload distribution
- Data residency management
- Cross-region replication
- Hybrid connectivity
- Cost optimization
- Disaster recovery
- Compliance mapping

**Key Components:**
- `orchestrator.py` - Deployment orchestration
- `detector.py` - Environment detection
- `sync_engine.py` - Cross-cloud sync
- `config_manager.py` - Configuration management
- `registry.py` - Service registry

### Admin CRUD Module (`admin_crud/`)
Auto-generated admin interfaces.

**Features:**
- Automatic CRUD generation
- Model introspection
- Form generation
- Validation rules
- Relationship handling
- Bulk operations
- Export/import
- Audit trail integration

**Key Components:**
- `generator.py` - CRUD generation logic
- `templates.py` - UI templates
- `models.py` - CRUD metadata

## Module Integration Patterns

### Security Integration
All modules integrate with the core security module:
- Input validation through `validators.py`
- Encryption using `SecurityUtils`
- Tenant isolation via middleware
- Audit logging for sensitive operations

### Database Patterns
All modules follow consistent database patterns:
- Models extend `TenantMixin` for multi-tenancy
- Use `TimestampMixin` for audit fields
- Implement soft deletes where appropriate
- Use SQLAlchemy ORM for queries

### API Patterns
Consistent API design across modules:
- RESTful endpoints with OpenAPI docs
- Consistent error responses
- Rate limiting on all endpoints
- JWT authentication required
- Request/response validation with Pydantic

### Configuration
Modules share configuration patterns:
- Environment variable configuration
- Secure secret management
- Feature flags for optional functionality
- Tenant-specific overrides

## Module Dependencies

### Dependency Graph
```
core
├── auth (depends on core)
├── admin (depends on core, auth)
├── billing (depends on core, auth)
├── observability (depends on core)
├── privacy (depends on core, auth)
├── mcp_auth (depends on core, auth)
├── telemetry (depends on core, privacy)
├── whitelabel (depends on core, auth, admin)
├── security_advanced (depends on core, auth)
├── billing_advanced (depends on core, auth, billing)
├── enterprise_sso (depends on core, auth)
├── performance (depends on core, observability)
├── marketplace (depends on core, auth, billing)
├── edge_deployment (depends on core, security_advanced)
├── hybrid_deployment (depends on core, edge_deployment)
└── admin_crud (depends on core, admin)
```

### External Dependencies
Common external dependencies across modules:
- `fastapi` - Web framework
- `sqlalchemy` - ORM
- `pydantic` - Data validation
- `redis` - Caching and rate limiting
- `celery` - Background tasks
- `prometheus-client` - Metrics
- `cryptography` - Encryption
- `httpx` - HTTP client

## Testing Modules

Each module includes comprehensive tests:
- Unit tests for business logic
- Integration tests for API endpoints
- Security tests for vulnerabilities
- Performance tests for scalability
- Mock implementations for external services

Run module-specific tests:
```bash
pytest modules/auth/tests/
pytest modules/billing/tests/
pytest -m security  # Security-focused tests
```

## Adding New Modules

To create a new module:

1. Create module directory: `modules/new_module/`
2. Implement required files:
   - `__init__.py` - Module initialization
   - `models.py` - Data models
   - `routes.py` - API endpoints
   - `services.py` - Business logic
   - `README.md` - Documentation
3. Update manifest parser in `generator/manifest.py`
4. Add module registration in `modules/core/app.py`
5. Create tests in `modules/new_module/tests/`
6. Update this documentation

## Module Configuration

Modules can be configured via:
1. Manifest YAML files
2. Environment variables
3. Runtime configuration API
4. Tenant-specific settings

Example manifest configuration:
```yaml
modules:
  - name: auth
    config:
      mfa_required: true
      session_timeout: 3600
  - name: billing
    config:
      provider: stripe
      webhook_secret: ${STRIPE_WEBHOOK_SECRET}
  - name: telemetry
    config:
      sample_rate: 0.1
      privacy_mode: strict
```

## Best Practices

1. **Modularity**: Keep modules focused on single responsibilities
2. **Security**: Always validate input and sanitize output
3. **Testing**: Maintain high test coverage (>80%)
4. **Documentation**: Keep README files updated
5. **Performance**: Consider caching and async operations
6. **Compatibility**: Ensure backward compatibility
7. **Monitoring**: Add metrics and logging
8. **Error Handling**: Provide meaningful error messages