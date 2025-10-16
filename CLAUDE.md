# Inevitable Cloud Stack - Claude AI Assistant Guide

## Project Overview

The Inevitable Cloud Stack is a unified gateway system and shared infrastructure for the Inevitable product ecosystem. It provides centralized authentication, multi-tenant architecture, and routing for SignalPattern, PrismEngine, and PlatformForge products.

**Repository**: `/Users/davidthomson/Projects/inevitable-cloud-stack`
**Architecture**: Multi-Product Gateway System
**Status**: Production-Ready with PlatformForge Integration Complete

## 🏗️ System Architecture

The cloud stack implements a plugin-based gateway architecture where products integrate via entry points:

### Core Components
1. **core-identity** - Shared authentication, tenant, and entitlement logic
2. **cloud-gateway** - FastAPI host router with admin dashboard and routing
3. **Product Integration** - Plugin system for external products

### Integration Model
Products integrate by implementing entry points:
- **Router Entry Point**: `inevitable.gateway.router`
- **Tasks Entry Point**: `inevitable.gateway.tasks`
- **Host-Based Routing**: Domain patterns and path prefixes
- **Shared Authentication**: JWT tokens through core-identity

## 📁 Project Structure

```
inevitable-cloud-stack/
├── inevitable/                     # Core infrastructure modules
│   ├── core-identity/             # Shared authentication service
│   │   ├── modules/               # Core modules (auth, database, security)
│   │   ├── alembic/              # Database migrations
│   │   └── requirements.txt       # Python dependencies
│   ├── cloud-gateway/            # FastAPI gateway router
│   │   ├── app/                  # Gateway application
│   │   ├── routers/              # Product routing logic
│   │   └── middleware/           # Gateway middleware
│   └── docs/                     # Integration documentation
│       ├── integration-blueprint.md
│       └── gateway-integration-plan.md
├── PLATFORMFORGE_GATEWAY_INTEGRATION_STATUS.md  # PlatformForge status
├── ARCHITECTURE_ANALYSIS.md      # System architecture analysis
├── STACK_INVENTORY.md            # Component inventory
├── README.md                     # Project overview
└── CLAUDE.md                     # This file
```

## 🔗 Product Integration Status

### ✅ PlatformForge (COMPLETE)
- **Integration Type**: Multi-Product Gateway
- **Entry Points**: `platform_forge_cloud.gateway:load_router`, `platform_forge_cloud.gateway:register_tasks`
- **Host Patterns**: `platformforge.ai`, `*.platformforge.ai`
- **Path Prefix**: `/platformforge`
- **Authentication**: JWT with core-identity
- **Background Tasks**: Health checks, quota sync, platform cleanup
- **Security**: Environment-based deployment contexts
- **Status**: ✅ PRODUCTION READY

### 🔄 SignalPattern (IN PROGRESS)
- **Status**: Core integration working, gateway routing planned
- **Authentication**: Compatible JWT tokens
- **Deployment**: Railway (independent)

### 🔄 PrismEngine (PLANNED)
- **Status**: Gateway integration planned
- **Authentication**: Will use shared core-identity
- **Deployment**: Railway (independent)

## 🚀 Essential Commands

### Core-Identity Service

```bash
# Navigate to core-identity
cd inevitable/core-identity

# Install dependencies
pip install -r requirements.txt

# Run core-identity service
PORT=3333 python -m modules.core.main

# With custom database
DATABASE_URL="sqlite:///./platform_forge.db" PORT=3333 python -m modules.core.main

# Database migrations
alembic upgrade head
```

### Cloud Gateway

```bash
# Navigate to cloud-gateway
cd inevitable/cloud-gateway

# Install dependencies
pip install -r requirements.txt

# Run gateway service
python app/main.py

# With specific port
PORT=8080 python app/main.py
```

### Testing Gateway Integration

```bash
# Test PlatformForge integration
cd ../platformforge/platform-forge-cloud
python test_gateway_integration.py

# Verify entry points
python -c "import pkg_resources; print(list(pkg_resources.iter_entry_points('inevitable.gateway.router')))"
python -c "import pkg_resources; print(list(pkg_resources.iter_entry_points('inevitable.gateway.tasks')))"
```

## 🔧 Development Workflow

### Adding New Product Integration

1. **Entry Points Setup**
   ```toml
   [project.entry-points]
   "inevitable.gateway.router" = "your_product.gateway:load_router"
   "inevitable.gateway.tasks" = "your_product.gateway:register_tasks"
   ```

2. **Router Implementation**
   ```python
   def load_router() -> FastAPI:
       """Return FastAPI sub-application for product"""
       # Authentication middleware
       # Product-specific routes
       # Health checks
       return app
   ```

3. **Tasks Implementation**
   ```python
   def register_tasks() -> Dict[str, Any]:
       """Return background tasks configuration"""
       return {
           "service": "product_name",
           "tasks": {...},
           "queues": [...],
           "dependencies": ["core-identity"]
       }
   ```

4. **Configuration**
   ```python
   GATEWAY_CONFIG = {
       "service_name": "product",
       "host_patterns": ["product.ai", "*.product.ai"],
       "path_prefix": "/product",
       "auth_required": True,
       "health_endpoint": "/health"
   }
   ```

### Authentication Integration

```python
# Using core-identity JWT tokens
from inevitable.core_identity.auth import verify_jwt_token

async def get_current_user(token: str = Depends(security)):
    payload = verify_jwt_token(token.credentials)
    user_id = payload.get("sub")
    tenant_id = payload.get("tenant_id")
    # Validate user in your product's database
    return user
```

### Host-Based Routing

```yaml
# Gateway routing configuration
services:
  product:
    hosts: ["product.ai", "*.product.ai"]
    path_prefix: "/product"
    auth_required: true
    health_endpoint: "/health"
```

## 🔒 Security Architecture

### Multi-Tenant Authentication
- **Core-Identity Service**: Centralized user and tenant management
- **JWT Tokens**: Include user and tenant context
- **Database Isolation**: Tenant-scoped queries in all products
- **API Security**: All routes require authentication through gateway

### Deployment Security
- **Environment Contexts**: Separate internal vs customer deployments
- **Credential Isolation**: No development credentials in customer environments
- **HTTPS Enforcement**: All traffic encrypted in transit
- **Rate Limiting**: Gateway-level protection

### Product Security Boundaries
- **Independent Databases**: Each product manages its own data
- **Shared Auth Context**: Common user/tenant validation
- **Service Isolation**: Products can't access each other's data
- **Gateway-Enforced**: Authentication and authorization at entry point

## 🧪 Testing Strategy

### Integration Testing
```bash
# Test core-identity service
cd inevitable/core-identity
python -m pytest tests/

# Test gateway routing
cd inevitable/cloud-gateway
python -m pytest tests/

# Test product integration
cd ../product-repo
python test_gateway_integration.py
```

### End-to-End Testing
```bash
# Start all services
cd inevitable/core-identity && PORT=3333 python -m modules.core.main &
cd inevitable/cloud-gateway && PORT=8080 python app/main.py &

# Test authentication flow
curl -X POST http://localhost:3333/auth/login -d '{"username":"test","password":"test"}'

# Test product routing
curl -H "Authorization: Bearer $TOKEN" http://localhost:8080/product/health
```

### Load Testing
```bash
# Gateway performance testing
ab -n 1000 -c 10 http://localhost:8080/health

# Product integration testing
ab -n 100 -c 5 -H "Authorization: Bearer $TOKEN" http://localhost:8080/product/api/endpoint
```

## 📊 Monitoring and Observability

### Health Checks
- **Core-Identity**: `/health` endpoint with database connectivity
- **Gateway**: `/health` with service status aggregation
- **Products**: Individual health endpoints at `/product/health`

### Metrics Collection
- **Gateway Metrics**: Request count, latency, error rates
- **Authentication Metrics**: Login success/failure rates
- **Product Metrics**: Individual service metrics via background tasks

### Logging
- **Structured Logging**: JSON format for all services
- **Request Tracing**: Correlation IDs across service boundaries
- **Security Events**: Authentication, authorization, failures

## 🔄 Background Tasks

### Core System Tasks
- **Token Cleanup**: Expired JWT token removal
- **Health Monitoring**: Service availability checks
- **Metrics Aggregation**: System-wide performance data

### Product-Specific Tasks
Products register their own background tasks:
```python
{
    "cleanup_data": {
        "schedule": "0 2 * * *",  # Daily at 2 AM
        "description": "Clean up expired data",
        "function": "product.tasks.cleanup"
    },
    "sync_quotas": {
        "schedule": "*/15 * * * *",  # Every 15 minutes
        "description": "Sync user quotas",
        "function": "product.tasks.sync_quotas"
    }
}
```

## 🔍 Troubleshooting

### Common Issues

#### Authentication Failures
```bash
# Check core-identity service
curl http://localhost:3333/health

# Verify JWT token
python -c "
import jwt
token = 'your_jwt_token'
print(jwt.decode(token, verify=False))
"

# Check user in database
cd inevitable/core-identity
python -c "
from modules.core.database import get_db
from modules.auth.models import User
with get_db() as db:
    users = db.query(User).all()
    print(f'Found {len(users)} users')
"
```

#### Gateway Routing Issues
```bash
# Check entry points
python -c "
import pkg_resources
routers = list(pkg_resources.iter_entry_points('inevitable.gateway.router'))
tasks = list(pkg_resources.iter_entry_points('inevitable.gateway.tasks'))
print(f'Routers: {[ep.name for ep in routers]}')
print(f'Tasks: {[ep.name for ep in tasks]}')
"

# Test product router loading
python -c "
import platform_forge_cloud
router = platform_forge_cloud.load_router()
print(f'Router type: {type(router)}')
"
```

#### Database Connection Issues
```bash
# Check database connectivity
cd inevitable/core-identity
python -c "
from modules.core.database import engine
try:
    with engine.connect() as conn:
        print('✅ Database connected')
except Exception as e:
    print(f'❌ Database error: {e}')
"

# Run migrations
alembic upgrade head
```

#### Product Integration Issues
```bash
# Verify product package imports
python -c "import platform_forge_cloud; print('✅ PlatformForge imports')"

# Check environment variables
python -c "
import os
required = ['SECRET_KEY', 'DATABASE_URL']
for var in required:
    value = os.getenv(var)
    print(f'{var}: {\"SET\" if value else \"MISSING\"}')
"
```

### Performance Issues
- **Database Queries**: Use connection pooling and query optimization
- **Gateway Latency**: Monitor request routing overhead
- **Memory Usage**: Monitor service memory consumption
- **Background Tasks**: Check task queue performance

## 📚 Key Files for Common Tasks

### Gateway Development
- **Core Gateway**: `inevitable/cloud-gateway/app/main.py`
- **Product Routing**: `inevitable/cloud-gateway/routers/`
- **Authentication Middleware**: `inevitable/cloud-gateway/middleware/auth.py`

### Authentication Development
- **Core Auth Service**: `inevitable/core-identity/modules/auth/service.py`
- **User Models**: `inevitable/core-identity/modules/auth/models.py`
- **JWT Handling**: `inevitable/core-identity/modules/auth/jwt.py`

### Product Integration
- **PlatformForge Example**: `../platformforge/platform-forge-cloud/platform_forge_cloud/gateway.py`
- **Entry Points**: Product `pyproject.toml` files
- **Integration Tests**: Product `test_gateway_integration.py` files

### Documentation
- **Integration Blueprint**: `inevitable/docs/integration-blueprint.md`
- **Gateway Plan**: `inevitable/docs/gateway-integration-plan.md`
- **PlatformForge Status**: `PLATFORMFORGE_GATEWAY_INTEGRATION_STATUS.md`

## 🌐 Production Deployment

### Environment Configuration
```bash
# Core-Identity Service
DATABASE_URL=postgresql://user:pass@host:5432/core_identity
SECRET_KEY=your_secure_secret_key
PORT=3333

# Gateway Service
CORE_IDENTITY_URL=http://localhost:3333
GATEWAY_PORT=8080
CORS_ORIGINS=["https://yourdomain.com"]

# Product Services
PLATFORMFORGE_DEPLOYMENT_CONTEXT=internal
PRODUCT_DATABASE_URL=postgresql://user:pass@host:5432/product_db
```

### Deployment Checklist
- ✅ Core-identity service running and healthy
- ✅ Product databases initialized with proper migrations
- ✅ All required environment variables set
- ✅ HTTPS configured for production
- ✅ Product entry points properly configured
- ✅ Health checks responding correctly
- ✅ Background tasks scheduled and running
- ✅ Monitoring and alerting configured

### Scaling Considerations
- **Load Balancing**: Multiple gateway instances behind load balancer
- **Database Scaling**: Read replicas for core-identity
- **Product Independence**: Scale products independently
- **Cache Layer**: Redis for session and frequently accessed data

## 🔮 Future Development

### Planned Features
1. **Admin Dashboard**: Management interface for the entire stack
2. **API Gateway**: Advanced routing, rate limiting, transformation
3. **Service Mesh**: Istio integration for advanced networking
4. **Observability**: Prometheus, Grafana, distributed tracing
5. **CI/CD Pipeline**: Automated testing and deployment

### Integration Roadmap
1. **Phase 1**: ✅ PlatformForge integration (COMPLETE)
2. **Phase 2**: 🔄 SignalPattern v2 gateway integration
3. **Phase 3**: 🔄 PrismEngine gateway integration
4. **Phase 4**: 📋 Unified admin dashboard
5. **Phase 5**: 📋 Advanced API gateway features

## 📞 Support and Contact

- **Development Team**: Inevitable Co
- **Repository**: Private GitHub repository
- **Integration Status**: See `PLATFORMFORGE_GATEWAY_INTEGRATION_STATUS.md`
- **Architecture**: See `ARCHITECTURE_ANALYSIS.md`
- **Stack Inventory**: See `STACK_INVENTORY.md`

---

**Note**: This cloud stack is the foundation for Inevitable's multi-product ecosystem. PlatformForge integration is complete and production-ready. All future products should follow the same integration patterns established with PlatformForge.