# Invitable Cloud Stack

This workspace collects the Invitable product repos alongside the shared gateway plan.

## Layout
- `invitable/core-identity` – shared auth, tenant, entitlement logic to be packaged as `core_identity`
- `invitable/prismengine` – PrismEngine application code that will consume `core_identity`
- `invitable/platformforge` – PlatformForge Cloud service
- `invitable/cloud-gateway` – new FastAPI host router that mounts each product package
- `invitable/docs` – integration plan and blueprint for the unified deployment

See `invitable/docs/integration-blueprint.md` for the roadmap and `invitable/docs/gateway-integration-plan.md` for the detailed gateway structure.
