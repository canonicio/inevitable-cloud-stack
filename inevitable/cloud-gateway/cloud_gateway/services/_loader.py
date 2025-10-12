from __future__ import annotations

from importlib import import_module
from typing import Iterable

from fastapi import APIRouter


def _find_attribute(candidates: Iterable[str], attribute: str):
    for dotted_path in candidates:
        try:
            module = import_module(dotted_path)
        except ModuleNotFoundError:
            continue
        attr = getattr(module, attribute, None)
        if callable(attr):
            return attr
    return None


def load_router(product: str, candidates: Iterable[str]) -> APIRouter:
    loader = _find_attribute(candidates, "load_router")
    if loader:
        return loader()

    router = APIRouter()

    @router.get("/health", tags=[product])
    def healthcheck() -> dict[str, str]:
        return {"status": "ok", "product": product}

    return router


def register_tasks(celery_app, candidates: Iterable[str]) -> None:
    registrar = _find_attribute(candidates, "register_tasks")
    if registrar:
        registrar(celery_app)
