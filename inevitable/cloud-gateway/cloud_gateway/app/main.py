from __future__ import annotations

from typing import Dict

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .dependencies import product_context_dependency
from .host_router import HostRouterMiddleware
from .settings import settings
from .telemetry import configure_logging
from ..services import platformforge, prism, signalpattern

_logger = configure_logging()

SERVICES = {
    "prism": prism,
    "platformforge": platformforge,
    "signalpattern": signalpattern,
}

app = FastAPI(title="Invitable Cloud Gateway")


@app.on_event("startup")
async def log_startup() -> None:
    _logger.info("cloud-gateway startup complete", extra={"invitable_product": "gateway"})


def _configure_cors(application: FastAPI) -> None:
    origins = {
        origin
        for product_config in settings.products.values()
        for origin in product_config.cors_origins
    }
    if origins:
        application.add_middleware(
            CORSMiddleware,
            allow_origins=sorted(origins),
            allow_credentials=True,
            allow_methods=["*"],
            allow_headers=["*"],
        )


def _mount_service_routes(application: FastAPI) -> None:
    for name, module in SERVICES.items():
        prefix = settings.prefix_for(name)
        if not prefix:
            _logger.warning("Skipping %s; no prefix configured", name)
            continue
        router = module.load_router()
        application.include_router(
            router,
            prefix=prefix,
            dependencies=[product_context_dependency(name)],
        )


_configure_cors(app)
app.add_middleware(HostRouterMiddleware)
_mount_service_routes(app)


@app.get("/healthz", tags=["gateway"])
async def healthcheck() -> Dict[str, str]:
    return {"status": "ok"}
