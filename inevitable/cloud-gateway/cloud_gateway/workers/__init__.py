"""Celery worker wiring for the cloud gateway."""

from .celery_app import celery_app

__all__ = ["celery_app"]
