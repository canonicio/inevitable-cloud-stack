# Inevitable Cloud Stack

This workspace contains the shared infrastructure and gateway for the Inevitable product ecosystem.

## Layout
- `inevitable/core-identity` – Shared authentication, tenant, and entitlement logic packaged as `core_identity`
- `inevitable/cloud-gateway` – FastAPI host router that provides admin dashboard and routing
- `inevitable/docs` – Integration plans and architecture blueprints

## Product Repositories
The following products integrate with this infrastructure:
- **SignalPattern** - AI-powered research and strategy platform
- **PrismEngine** - Intelligence automation platform
- **PlatformForge** - Platform builder product

Each product is maintained in its own repository and deployed independently to Railway.

## Architecture
See `inevitable/docs/integration-blueprint.md` for the roadmap and `inevitable/docs/gateway-integration-plan.md` for the detailed gateway structure.
