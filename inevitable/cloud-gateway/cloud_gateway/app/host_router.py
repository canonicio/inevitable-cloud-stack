from __future__ import annotations

from starlette.datastructures import MutableHeaders
from starlette.types import ASGIApp, Receive, Scope, Send

from .settings import settings


class HostRouterMiddleware:
    """Middleware that rewrites incoming requests according to the Host header."""

    def __init__(self, app: ASGIApp, *, settings_override=None) -> None:
        self.app = app
        self._settings = settings_override or settings

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope.get("type") not in {"http", "websocket"}:
            await self.app(scope, receive, send)
            return

        headers = MutableHeaders(scope=scope)
        host_header = headers.get("host")
        product = None
        if host_header:
            hostname = host_header.split(":", 1)[0]
            product = self._settings.product_for_host(hostname)

        if product:
            prefix = self._settings.prefix_for(product)
            if prefix:
                new_path = self._rewrite_path(scope["path"], prefix)
                if new_path != scope["path"]:
                    scope = dict(scope)
                    scope["path"] = new_path
                    scope["raw_path"] = new_path.encode("ascii")
                    headers = MutableHeaders(scope=scope)
                state = scope.setdefault("state", {})
                state["invitable_product"] = product
                headers["x-invitable-product"] = product

        await self.app(scope, receive, send)

    @staticmethod
    def _rewrite_path(path: str, prefix: str) -> str:
        normalized_prefix = prefix.rstrip("/") or "/"
        if path == normalized_prefix or path.startswith(normalized_prefix + "/"):
            return path
        if path == "/":
            return normalized_prefix
        if normalized_prefix == "/":
            return path
        return f"{normalized_prefix}{path}"
