
# Tenant Config
# Provides schema-level or row-level isolation logic

TENANT_DB_MAP = {
    "default": "postgresql://localhost/default",
    "acme": "postgresql://localhost/acme"
}

def get_tenant_db_url(tenant_id: str) -> str:
    return TENANT_DB_MAP.get(tenant_id, TENANT_DB_MAP["default"])
