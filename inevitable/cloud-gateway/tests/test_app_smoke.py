from __future__ import annotations

from fastapi.testclient import TestClient

from cloud_gateway.app import app


def test_healthcheck():
    client = TestClient(app)
    response = client.get("/healthz")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_prism_fallback_router():
    client = TestClient(app)
    response = client.get("/api/prism/health")
    assert response.status_code == 200
    body = response.json()
    assert body["product"] == "prism"


def test_host_header_rewrite():
    client = TestClient(app)
    response = client.get("/health", headers={"host": "prismengine.ai"})
    assert response.status_code == 200
    assert response.json()["product"] == "prism"
