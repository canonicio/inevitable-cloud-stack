"""Cloud Gateway application package."""

from .main import app  # re-export for ASGI tooling

__all__ = ["app"]
