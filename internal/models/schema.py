# internal/models/schema.py

from __future__ import annotations

SCHEMA_VERSION = "0.1"

BASE_SCHEMA = {
    "schema_version": SCHEMA_VERSION,
    # RFC3339/ISO8601 UTC with Z suffix
    "scanned_at": None,
    "docker": {
        "containers": [],
        "images": [],
        "networks": [],
        "volumes": [],
        "stacks": [],
    },
}
