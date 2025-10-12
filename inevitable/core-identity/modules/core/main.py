"""
Main entry point for Platform Forge generated applications
"""
import os
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

# Load environment variables
from dotenv import load_dotenv
load_dotenv()

import uvicorn
from modules.core.app import create_app

# Load configuration from manifest or environment
def get_config():
    """Load configuration from environment or manifest"""
    # HIGH-003 FIX: Use secure YAML loading with bomb protection
    from modules.core.security import safe_load_yaml, YAMLBombError
    
    # Check if we have a manifest file
    manifest_path = os.getenv("MANIFEST_PATH", "manifest_applied.yaml")
    if os.path.exists(manifest_path):
        try:
            manifest = safe_load_yaml(manifest_path)
        except (YAMLBombError, FileNotFoundError, ValueError) as e:
            print(f"Warning: Could not load manifest file {manifest_path}: {e}")
            manifest = {}
    else:
        manifest = {}
    
    return {
        "name": manifest.get("name", os.getenv("APP_NAME", "Platform Forge")),
        "deployment": manifest.get("deployment", "docker"),
        "modules": manifest.get("modules", ["auth", "admin", "billing", "observability", "privacy", "prism"]),
        "tenancy": manifest.get("tenancy", "multi"),
        "enable_multitenancy": manifest.get("tenancy", "multi") == "multi",
    }

# Create the application
config = get_config()
app = create_app(
    title=config["name"],
    version="1.0.0",
    enable_multitenancy=config["enable_multitenancy"],
    modules=config["modules"]
)

if __name__ == "__main__":
    # Development server
    uvicorn.run(
        "modules.core.main:app",
        host=os.getenv("HOST", "0.0.0.0"),
        port=int(os.getenv("PORT", 8000)),
        reload=os.getenv("DEBUG", "false").lower() == "true",
        log_level=os.getenv("LOG_LEVEL", "info").lower()
    )