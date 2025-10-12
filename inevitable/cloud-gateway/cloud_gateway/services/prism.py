from __future__ import annotations

from fastapi import APIRouter

from ._loader import load_router as _load_router, register_tasks as _register_tasks

_ROUTER_CANDIDATES = (
    "prismengine.gateway",
    "prismengine.app",
)

_TASK_CANDIDATES = (
    "prismengine.tasks",
    "prismengine.worker",
)


def load_router() -> APIRouter:
    return _load_router("prism", _ROUTER_CANDIDATES)


def register_tasks(celery_app) -> None:
    _register_tasks(celery_app, _TASK_CANDIDATES)
