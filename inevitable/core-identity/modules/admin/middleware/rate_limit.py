
from fastapi import Request, HTTPException
from starlette.middleware.base import BaseHTTPMiddleware
import time

# Example in-memory store for request counts (not suitable for prod)
request_counts = {}

TENANT_LIMITS = {
    "default": 100,  # max requests per window
    "acme": 1000
}
WINDOW_SECONDS = 60

class RateLimitMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        tenant = request.headers.get("X-Tenant-ID", "default")
        key = f"{tenant}:{int(time.time() // WINDOW_SECONDS)}"

        count = request_counts.get(key, 0)
        limit = TENANT_LIMITS.get(tenant, TENANT_LIMITS["default"])

        if count >= limit:
            raise HTTPException(status_code=429, detail="Rate limit exceeded")

        request_counts[key] = count + 1
        response = await call_next(request)
        return response
