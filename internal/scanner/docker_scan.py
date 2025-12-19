import copy
from datetime import datetime

import docker

from internal.models.schema import BASE_SCHEMA


def _labels(attrs: dict) -> dict:
    return (attrs.get("Config") or {}).get("Labels") or {}


def _stack_key(labels: dict) -> tuple[str, str]:
    # returns (kind, name)
    if labels.get("com.docker.compose.project"):
        return ("compose", labels["com.docker.compose.project"])
    if labels.get("com.portainer.stack.name"):
        return ("portainer", labels["com.portainer.stack.name"])
    return ("ungrouped", "ungrouped")


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
        labels = _labels(attrs)
        kind, stack_name = _stack_key(labels)

        containers.append({
            "id": c.id,
            "name": c.name,
            "image": c.image.tags,
            "status": c.status,
            "created": created,
            "stack": {"kind": kind, "name": stack_name},
            "compose": {
                "project": labels.get("com.docker.compose.project"),
                "service": labels.get("com.docker.compose.service"),
                "working_dir": labels.get("com.docker.compose.project.working_dir"),
                "config_files": labels.get("com.docker.compose.project.config_files"),
            } if labels.get("com.docker.compose.project") else None,
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

    # Build stacks from containers
    stacks_map = {}
    for c in containers:
        sk = c["stack"]["kind"]
        sn = c["stack"]["name"]
        key = f"{sk}:{sn}"
        stacks_map.setdefault(key, {
            "kind": sk,
            "name": sn,
            "containers": [],
            "services": {},
        })

        stacks_map[key]["containers"].append({
            "id": c["id"],
            "name": c["name"],
            "status": c["status"],
            "image": c["image"],
        })

        comp = c.get("compose") or {}
        svc = comp.get("service")
        if svc:
            stacks_map[key]["services"].setdefault(svc, 0)
            stacks_map[key]["services"][svc] += 1

    stacks = list(stacks_map.values())

    # Stable ordering (deterministic output)
    stacks.sort(key=lambda s: (s["kind"], s["name"]))
    for s in stacks:
        s["containers"].sort(key=lambda x: x["name"])

    result = copy.deepcopy(BASE_SCHEMA)
    result["scanned_at"] = datetime.utcnow().isoformat() + "Z"
    result["docker"]["containers"] = containers
    result["docker"]["images"] = images
    result["docker"]["networks"] = networks
    result["docker"]["volumes"] = volumes
    result["docker"]["stacks"] = stacks

    return result
