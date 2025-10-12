from __future__ import annotations

from typing import Any, Dict

from fastapi import Depends, HTTPException, Request, status

from .settings import settings


def product_context_dependency(product: str):
    """Return a dependency that validates the caller can access *product*."""

    async def _dependency(request: Request) -> Dict[str, Any]:
        if product not in settings.products:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Product '{product}' is not configured",
            )

        # TODO: integrate with core_identity to validate tenant entitlements.
        request_product = getattr(request.state, "invitable_product", product)
        return {
            "product": product,
            "host_product": request_product,
        }

    return Depends(_dependency)
