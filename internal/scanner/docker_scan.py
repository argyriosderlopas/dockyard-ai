# internal/scanner/docker_scan.py

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


def _container_networks(attrs: dict) -> list[str]:
    nets = ((attrs.get("NetworkSettings") or {}).get("Networks") or {})
    return sorted(list(nets.keys()))


def _container_named_volumes(attrs: dict) -> list[str]:
    mounts = attrs.get("Mounts") or []
    names = []
    for m in mounts:
        # Named Docker volumes only (not bind mounts)
        if m.get("Type") == "volume" and m.get("Name"):
            names.append(m["Name"])
    return sorted(names)


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

        c_networks = _container_networks(attrs)
        c_volumes = _container_named_volumes(attrs)

        containers.append(
            {
                "id": c.id,
                "name": c.name,
                "image": c.image.tags,
                "status": c.status,
                "created": created,
                "stack": {"kind": kind, "name": stack_name},
                "compose": (
                    {
                        "project": labels.get("com.docker.compose.project"),
                        "service": labels.get("com.docker.compose.service"),
                        "working_dir": labels.get("com.docker.compose.project.working_dir"),
                        "config_files": labels.get("com.docker.compose.project.config_files"),
                    }
                    if labels.get("com.docker.compose.project")
                    else None
                ),
                "networks": c_networks,
                "volumes": c_volumes,
            }
        )

    images = []
    for i in client.images.list():
        attrs = i.attrs or {}
        images.append(
            {
                "id": i.id,
                "tags": i.tags,
                "size": attrs.get("Size"),
            }
        )

    networks = []
    for n in client.networks.list():
        attrs = n.attrs or {}
        labels = attrs.get("Labels") or {}
        kind, stack_name = _stack_key(labels)

        networks.append(
            {
                "id": n.id,
                "name": n.name,
                "driver": attrs.get("Driver"),
                "scope": attrs.get("Scope"),
                "stack": {"kind": kind, "name": stack_name} if kind != "ungrouped" else None,
            }
        )

    volumes = []
    for v in client.volumes.list():
        attrs = v.attrs or {}
        labels = attrs.get("Labels") or {}
        kind, stack_name = _stack_key(labels)

        volumes.append(
            {
                "name": attrs.get("Name"),
                "driver": attrs.get("Driver"),
                "mountpoint": attrs.get("Mountpoint"),
                "stack": {"kind": kind, "name": stack_name} if kind != "ungrouped" else None,
            }
        )

    # Build stacks from containers (source of truth)
    stacks_map = {}
    for c in containers:
        sk = c["stack"]["kind"]
        sn = c["stack"]["name"]
        key = f"{sk}:{sn}"

        stacks_map.setdefault(
            key,
            {
                "kind": sk,
                "name": sn,
                "containers": [],
                "services": {},
                "networks": set(),
                "volumes": set(),
            },
        )

        stacks_map[key]["containers"].append(
            {
                "id": c["id"],
                "name": c["name"],
                "status": c["status"],
                "image": c["image"],
            }
        )

        comp = c.get("compose") or {}
        svc = comp.get("service")
        if svc:
            stacks_map[key]["services"].setdefault(svc, 0)
            stacks_map[key]["services"][svc] += 1

        for nn in (c.get("networks") or []):
            stacks_map[key]["networks"].add(nn)

        for vn in (c.get("volumes") or []):
            stacks_map[key]["volumes"].add(vn)

    stacks = list(stacks_map.values())
    stacks.sort(key=lambda s: (s["kind"], s["name"]))

    for s in stacks:
        s["containers"].sort(key=lambda x: x["name"])
        s["networks"] = sorted(list(s["networks"]))
        s["volumes"] = sorted(list(s["volumes"]))

    result = copy.deepcopy(BASE_SCHEMA)
    result["scanned_at"] = datetime.utcnow().isoformat() + "Z"
    result["docker"]["containers"] = containers
    result["docker"]["images"] = images
    result["docker"]["networks"] = networks
    result["docker"]["volumes"] = volumes
    result["docker"]["stacks"] = stacks

    return result
