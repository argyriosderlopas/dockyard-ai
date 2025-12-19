# internal/scanner/docker_scan.py

import copy
from datetime import datetime

import docker

from internal.models.schema import BASE_SCHEMA


def _labels(attrs: dict) -> dict:
    return (attrs.get("Config") or {}).get("Labels") or {}


def _stack_key(labels: dict) -> tuple[str, str]:
    """
    Determine a container/network/volume stack identity based on known labels.
    Returns: (kind, name)
      - kind: compose | portainer | ungrouped
      - name: project/stack name or "ungrouped"
    """
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
    names: list[str] = []
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

    # ----------------------------
    # Containers
    # ----------------------------
    containers = []
    for c in client.containers.list(all=True):
        attrs = c.attrs or {}
        created = attrs.get("Created")

        labels = _labels(attrs)
        kind, stack_name = _stack_key(labels)

        c_networks = _container_networks(attrs)
        c_volumes = _container_named_volumes(attrs)

        compose_project = labels.get("com.docker.compose.project")
        containers.append(
            {
                "id": c.id,
                "name": c.name,
                "image": c.image.tags,
                "status": c.status,
                "created": created,
                "stack": {"kind": kind, "name": stack_name},
                "compose": {
                    "project": compose_project,
                    "service": labels.get("com.docker.compose.service"),
                    "working_dir": labels.get("com.docker.compose.project.working_dir"),
                    "config_files": labels.get("com.docker.compose.project.config_files"),
                }
                if compose_project
                else None,
                "networks": c_networks,
                "volumes": c_volumes,
            }
        )

    # ----------------------------
    # Images
    # ----------------------------
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

    # ----------------------------
    # Networks (include label-based stack hint when present)
    # ----------------------------
    networks = []
    for n in client.networks.list():
        attrs = n.attrs or {}
        nlabels = attrs.get("Labels") or {}
        nkind, nstack = _stack_key(nlabels)

        networks.append(
            {
                "id": n.id,
                "name": n.name,
                "driver": attrs.get("Driver"),
                "scope": attrs.get("Scope"),
                "stack": {"kind": nkind, "name": nstack} if nkind != "ungrouped" else None,
            }
        )

    # ----------------------------
    # Volumes (include label-based stack hint when present)
    # ----------------------------
    volumes = []
    for v in client.volumes.list():
        attrs = v.attrs or {}
        vlabels = attrs.get("Labels") or {}
        vkind, vstack = _stack_key(vlabels)

        volumes.append(
            {
                "name": attrs.get("Name"),
                "driver": attrs.get("Driver"),
                "mountpoint": attrs.get("Mountpoint"),
                "stack": {"kind": vkind, "name": vstack} if vkind != "ungrouped" else None,
            }
        )

    # ----------------------------
    # Build stacks from container truth
    # ----------------------------
    stacks_map: dict[str, dict] = {}

    for c in containers:
        sk = c["stack"]["kind"]
        sn = c["stack"]["name"]
        key = f"{sk}:{sn}"

        stacks_map.setdefault(
            key,
            {
                "kind": sk,
                "name": sn,
                # Stack-level meta (filled when available)
                "meta": {
                    "compose": None,      # dict when compose labels exist
                    "portainer": None,    # dict when portainer labels exist
                },
                # Contents
                "containers": [],
                "services": {},          # compose service -> count
                "networks": set(),       # derived from container attachments
                "volumes": set(),        # derived from container mounts
            },
        )

        # Minimal container summary inside stack
        stacks_map[key]["containers"].append(
            {
                "id": c["id"],
                "name": c["name"],
                "status": c["status"],
                "image": c["image"],
            }
        )

        # Compose service counts + stack meta
        comp = c.get("compose") or {}
        svc = comp.get("service")
        if svc:
            stacks_map[key]["services"][svc] = stacks_map[key]["services"].get(svc, 0) + 1

        # Stack-level compose metadata (first non-null wins, but we also merge safely)
        if sk == "compose":
            meta = stacks_map[key]["meta"].get("compose") or {
                "project": sn,
                "working_dir": None,
                "config_files": None,
            }
            if comp.get("working_dir") and not meta.get("working_dir"):
                meta["working_dir"] = comp.get("working_dir")
            if comp.get("config_files") and not meta.get("config_files"):
                meta["config_files"] = comp.get("config_files")
            stacks_map[key]["meta"]["compose"] = meta

        # Portainer stack meta (very lightweight; label availability varies)
        if sk == "portainer":
            # We only know the stack name reliably from grouping. Keep it explicit.
            stacks_map[key]["meta"]["portainer"] = stacks_map[key]["meta"].get("portainer") or {
                "stack_name": sn
            }

        # Networks/volumes derived from container usage
        for nn in (c.get("networks") or []):
            stacks_map[key]["networks"].add(nn)
        for vn in (c.get("volumes") or []):
            stacks_map[key]["volumes"].add(vn)

    stacks = list(stacks_map.values())

    # Deterministic ordering and set conversion
    stacks.sort(key=lambda s: (s["kind"], s["name"]))
    for s in stacks:
        s["containers"].sort(key=lambda x: x["name"])
        s["networks"] = sorted(list(s["networks"]))
        s["volumes"] = sorted(list(s["volumes"]))

        # Keep meta tidy: remove empty branches
        if s["meta"].get("compose") is None:
            s["meta"].pop("compose", None)
        if s["meta"].get("portainer") is None:
            s["meta"].pop("portainer", None)
        if not s["meta"]:
            s.pop("meta", None)

    # ----------------------------
    # Emit result
    # ----------------------------
    result = copy.deepcopy(BASE_SCHEMA)
    result["scanned_at"] = datetime.utcnow().isoformat() + "Z"

    result["docker"]["containers"] = containers
    result["docker"]["images"] = images
    result["docker"]["networks"] = networks
    result["docker"]["volumes"] = volumes
    result["docker"]["stacks"] = stacks

    return result
