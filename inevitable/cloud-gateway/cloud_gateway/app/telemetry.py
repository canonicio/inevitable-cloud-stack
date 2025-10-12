from __future__ import annotations

import logging


def configure_logging() -> logging.Logger:
    """Configure a shared logger for the gateway."""

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s [cloud-gateway] %(message)s",
    )
    return logging.getLogger("cloud-gateway")
