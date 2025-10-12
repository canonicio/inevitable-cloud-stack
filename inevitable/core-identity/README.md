# platform-forge-complete

A DeploymentType.SAAS application with auth, admin, billing, observability, privacy, mcp_auth, telemetry, referral_system, enterprise_sso modules

## Features- **Auth**: User authentication with JWT tokens and MFA support- **Admin**: Administrative dashboard with audit logs and user management- **Billing**: Stripe integration for subscriptions and payments- **Observability**: Prometheus metrics and structured logging- **Privacy**: GDPR compliance with consent management and data requests- **Mcp_auth**: Included- **Telemetry**: Included- **Referral_system**: Included- **Enterprise_sso**: Included
## Quick Start

### Using Docker Compose

```bash
docker-compose up -d
```

### Local Development

1. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

2. Set up environment:
   ```bash
   cp .env.example .env
   # Edit .env with your configuration
   ```

3. Run migrations:
   ```bash
   alembic upgrade head
   ```

4. Start the application:
   ```bash
   python -m modules.core.main
   ```

## Configuration

See `.env.example` for all available configuration options.

## API DocumentationWhen running in development mode, API documentation is available at:
- Swagger UI: http://localhost:8000/api/docs
- ReDoc: http://localhost:8000/api/redoc
## Deployment

This application supports multiple deployment strategies:
- **Docker**: Use the included Dockerfile and docker-compose.yml
- **Kubernetes**: Helm charts available in the k8s/ directory
- **SaaS**: Multi-tenant ready with tenant isolation

## Security

- JWT-based authentication
- Multi-factor authentication (MFA) support
- Rate limiting
- Tenant isolation (multi-tenant mode)
- Encrypted sensitive data

## Generated with Platform Forge

This application was generated using [Platform Forge](https://github.com/yourusername/platform-forge), 
a manifest-driven scaffolding system for production-ready SaaS/PaaS applications.
