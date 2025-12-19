# internal/models/schema.py

SCHEMA_VERSION = "0.1"

BASE_SCHEMA = {
    "schema_version": SCHEMA_VERSION,
    "scanned_at": None,
    "docker": {
        "containers": [],
        "images": [],
        "networks": [],
        "volumes": [],
        "stacks": [],
    },
}
