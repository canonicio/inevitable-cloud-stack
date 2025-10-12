> Gateway Integration Plan

  - Package Each Product
      - Convert prism-intelligence, platform-forge/platform-forge-cloud-enhanced, and signalpattern into installable Python packages (or keep
  their existing wheels if already present). Expose a load_router() (FastAPI) and optional load_tasks() entry point from each.
      - Publish artifacts to your internal package index or keep them as git dependencies so repos stay separate.
  - Create a Thin Gateway Repo (e.g. cloud-gateway/)
      - Layout:

        cloud-gateway/
          app/
            __init__.py
            main.py                # FastAPI instance
            host_router.py         # middleware mapping host → product path
            settings.py            # pulls shared + product configs via pydantic
            dependencies.py        # get_product_context(product)
            telemetry.py           # shared logging/OTel
          services/
            prism.py               # imports prism_intelligence.load_router()
            platformforge.py
            signalpattern.py
          workers/
            celery_app.py          # loads tasks from each package and namespaces queues
          requirements.txt         # pins product packages (git+https or internal wheel)
          Dockerfile               # FROM python:3.10-slim, pip install gateway + packages
          pyproject.toml
      - The ASGI app mounts each imported router twice:
          - Path-based (/api/prism, /api/platformforge, /api/signalpattern)
          - Host-based via middleware so Host: prismengine.ai rewrites to /api/prism.
  - Shared Auth & Tenant Core
      - Move core/auth/platform_forge_auth.py, belief_lattice/database customer models, and entitlement logic into a tiny package (e.g.
  core_identity) that all three products and the gateway depend on.
      - Extend PlatformForgeUser to carry entitlements; get_product_context(product) checks the tenant has access before allowing the route.
  - Database and Migrations
      - Keep a single Postgres instance. Each product continues to own its schema/migrations in its repo.
      - The gateway build step runs migrations in order (prism, platformforge, signalpattern) via a small orchestration script that imports each
  package’s Alembic env.
  - Celery / Background Services
      - Shared worker image installs the same three packages; environment variables toggle which queues it listens to. Queue names: prism.default,
  platformforge.analytics, signalpattern.pipeline.
      - Each product package exposes register_tasks(celery_app) so the gateway worker loads them conditionally.
  - Configuration / Secrets
      - Standardize env vars using double-underscore scoping:

        PRISM__FEATURE_FLAGS=...
        PLATFORMFORGE__SMTP_HOST=...
        SIGNALPATTERN__MODEL_BUCKET=...
      - The gateway’s Settings object hydrates product-specific subclasses and passes them into load_router().
  - Domains
      - Point prismengine.ai, platformforge.ai, signalpattern.ai to the same Railway/K8s service.
      - The host middleware in host_router.py maps domains to product prefixes. Optionally add per-host CORS and branding headers.
  - Observability
      - One OpenTelemetry pipeline with spans tagged by product. Shared metrics endpoint exported at /metrics, labelled with host.
      - Centralized request logging uses the compatibility dict you just reinstated (request.state.customer_auth).
  - CI/CD
      - Each product repo keeps its own CI; when a new release is tagged, publishing a wheel triggers the gateway repo to bump its dependency.
      - Gateway repo runs FastAPI TestClient smoke tests against /api/prism/..., /api/platformforge/..., /api/signalpattern/... (using host
  rewriting) before deploy.
