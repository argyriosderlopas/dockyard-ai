import copy
from datetime import datetime

import docker

from internal.models.schema import BASE_SCHEMA


def scan_docker_environment():
    try:
        client = docker.from_env()
        client.ping()
    except Exception as e:
        raise RuntimeError(f"Docker is not accessible from this host: {e}")

    containers = []
    for c in client.containers.list(all=True):
        attrs = c.attrs or {}
        created = attrs.get("Created")
        containers.append({
            "id": c.id,
            "name": c.name,
            "image": c.image.tags,
            "status": c.status,
            "created": created
        })

    images = []
    for i in client.images.list():
        attrs = i.attrs or {}
        images.append({
            "id": i.id,
            "tags": i.tags,
            "size": attrs.get("Size")
        })

    networks = []
    for n in client.networks.list():
        attrs = n.attrs or {}
        networks.append({
            "id": n.id,
            "name": n.name,
            "driver": attrs.get("Driver"),
            "scope": attrs.get("Scope")
        })

    volumes = []
    vols = client.volumes.list()
    for v in vols:
        attrs = v.attrs or {}
        volumes.append({
            "name": attrs.get("Name"),
            "driver": attrs.get("Driver"),
            "mountpoint": attrs.get("Mountpoint")
        })

    result = copy.deepcopy(BASE_SCHEMA)
    result["scanned_at"] = datetime.utcnow().isoformat() + "Z"
    result["docker"]["containers"] = containers
    result["docker"]["images"] = images
    result["docker"]["networks"] = networks
    result["docker"]["volumes"] = volumes

    return result
