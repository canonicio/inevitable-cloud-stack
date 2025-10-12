from __future__ import annotations

from celery import Celery

from cloud_gateway.services import platformforge, prism, signalpattern

celery_app = Celery("cloud_gateway")
celery_app.conf.update(
    task_default_queue="gateway.default",
    task_queues=[
        {"name": "prism.default"},
        {"name": "platformforge.analytics"},
        {"name": "signalpattern.pipeline"},
    ],
)

for service in (prism, platformforge, signalpattern):
    service.register_tasks(celery_app)


__all__ = ["celery_app"]
