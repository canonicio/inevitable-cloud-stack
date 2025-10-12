# Invitable Unified Backend Blueprint

  ## Goal
  Single gateway deploy serving PrismEngine, PlatformForge Cloud, and SignalPattern on separate domains, sharing auth/tenant context and
  infrastructure while keeping repos independent.

  ## Architecture
  - `cloud-gateway`: FastAPI app importing each product package and routing by host (`prismengine.ai`, `platformforge.ai`, `signalpattern.ai`).
  - `core-identity`: Shared auth, customer, entitlement models, and FastAPI dependencies.
  - Product packages expose `load_router()`, optional `register_tasks()` for Celery, and ship independent migrations.

  ## Deployment
  - One Docker image installing gateway + product wheels.
  - Railway/K8s service with three custom domains; middleware rewrites host→`/api/{product}`.
  - Shared Postgres/Redis with namespaced schemas & queues.

  ## Next Steps
  1. Move existing repos under `invitable/`.
  2. Extract shared auth/database into `core-identity`.
  3. Build `cloud-gateway` skeleton with host-routing middleware, config, and smoke tests.
  4. Add service-specific settings & Celery task registration.
  5. Configure CI/CD: product repos publish wheels; gateway pins versions and runs integration tests.

  After creating the directories, drop that file in invitable/docs/, and add a short README.md at the root pointing teams to the plan and listing
  each repo. Let me know when the folders are in place and I can help flesh out the gateway skeleton.