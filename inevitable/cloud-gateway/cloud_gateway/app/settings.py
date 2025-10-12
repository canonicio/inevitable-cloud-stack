from __future__ import annotations

from typing import Dict, Iterable, Optional

from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class ProductSettings(BaseModel):
    """Configuration shared by a single downstream product."""

    prefix: str = Field(
        ..., description="Path prefix the router for this product is mounted under."
    )
    hostnames: list[str] = Field(
        default_factory=list,
        description="Host headers that should resolve to this product.",
    )
    cors_origins: list[str] = Field(
        default_factory=list,
        description="CORS origins that should be appended when this product is active.",
    )

    def host_matches(self, host: str) -> bool:
        return host.lower() in (value.lower() for value in self.hostnames)


def _default_products() -> Dict[str, ProductSettings]:
    return {
        "prism": ProductSettings(
            prefix="/api/prism",
            hostnames=["prismengine.ai", "prism.local"],
        ),
        "platformforge": ProductSettings(
            prefix="/api/platformforge",
            hostnames=["platformforge.ai", "platformforge.local"],
        ),
        "signalpattern": ProductSettings(
            prefix="/api/signalpattern",
            hostnames=["signalpattern.ai", "signalpattern.local"],
        ),
    }


class Settings(BaseSettings):
    """Gateway configuration loaded from environment variables."""

    model_config = SettingsConfigDict(
        env_prefix="GATEWAY_",
        env_nested_delimiter="__",
        extra="ignore",
    )

    environment: str = Field(default="local")
    products: Dict[str, ProductSettings] = Field(default_factory=_default_products)

    def prefixes(self) -> Iterable[str]:
        return (product.prefix for product in self.products.values())

    def prefix_for(self, product: str) -> Optional[str]:
        config = self.products.get(product)
        return config.prefix if config else None

    def product_for_host(self, host: str) -> Optional[str]:
        host_lower = host.lower()
        for name, product in self.products.items():
            if product.host_matches(host_lower):
                return name
        return None


settings = Settings()
