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
        if m.get("Type") == "volume" and m.get("Name"):
            names.append(m["Name"])
    return sorted(names)


def _container_published_ports(attrs: dict) -> list[dict]:
    """
    Normalize published ports into a stable, readable list.
    Example output item:
      {"container_port": "80/tcp", "host_ip": "0.0.0.0", "host_port": "8080"}
    """
    ports = ((attrs.get("NetworkSettings") or {}).get("Ports") or {})
    out: list[dict] = []
    for container_port, bindings in ports.items():
        if not bindings:
            continue
        for b in bindings:
            out.append(
                {
                    "container_port": str(container_port),
                    "host_ip": b.get("HostIp"),
                    "host_port": b.get("HostPort"),
                }
            )
    out.sort(key=lambda x: (x.get("container_port") or "", x.get("host_ip") or "", x.get("host_port") or ""))
    return out


def _container_health(attrs: dict) -> str | None:
    state = attrs.get("State") or {}
    health = state.get("Health") or {}
    return health.get("Status")


def _container_restart_policy(attrs: dict) -> str | None:
    host_cfg = attrs.get("HostConfig") or {}
    rp = host_cfg.get("RestartPolicy") or {}
    return rp.get("Name")


def _container_mounts_breakdown(attrs: dict) -> dict:
    """
    Summarize mounts into:
      - bind_mounts: [{"source","destination","rw"}]
      - volume_mounts: [{"name","destination","rw"}]
    """
    mounts = attrs.get("Mounts") or []
    binds: list[dict] = []
    vols: list[dict] = []

    for m in mounts:
        mtype = m.get("Type")
        dst = m.get("Destination")
        rw = m.get("RW")

        if mtype == "bind":
            binds.append(
                {
                    "source": m.get("Source"),
                    "destination": dst,
                    "rw": bool(rw) if rw is not None else None,
                }
            )
        elif mtype == "volume":
            vols.append(
                {
                    "name": m.get("Name"),
                    "destination": dst,
                    "rw": bool(rw) if rw is not None else None,
                }
            )

    binds.sort(key=lambda x: (x.get("destination") or "", x.get("source") or ""))
    vols.sort(key=lambda x: (x.get("destination") or "", x.get("name") or ""))
    return {"bind_mounts": binds, "volume_mounts": vols}


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

        published_ports = _container_published_ports(attrs)
        health = _container_health(attrs)
        restart_policy = _container_restart_policy(attrs)
        mounts_breakdown = _container_mounts_breakdown(attrs)

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
                "runtime": {
                    "published_ports": published_ports,
                    "health": health,
                    "restart_policy": restart_policy,
                    "mounts": mounts_breakdown,
                },
            }
        )

    # Deterministic order for top-level container list
    containers.sort(key=lambda x: x.get("name") or "")

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
    images.sort(key=lambda x: (",".join(x.get("tags") or []), x.get("id") or ""))

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
    networks.sort(key=lambda x: x.get("name") or "")

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
    volumes.sort(key=lambda x: x.get("name") or "")

    # ----------------------------
    # Build stacks from container truth (plus stack meta)
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
                "meta": {
                    "compose": None,
                    "portainer": None,
                },
                "containers": [],
                "services": {},
                "networks": set(),
                "volumes": set(),
            },
        )

        comp = c.get("compose") or {}
        svc = comp.get("service")
        if svc:
            stacks_map[key]["services"][svc] = stacks_map[key]["services"].get(svc, 0) + 1

        # Stack-level meta
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

        if sk == "portainer":
            stacks_map[key]["meta"]["portainer"] = stacks_map[key]["meta"].get("portainer") or {"stack_name": sn}

        # Networks/volumes derived from container usage
        for nn in (c.get("networks") or []):
            stacks_map[key]["networks"].add(nn)
        for vn in (c.get("volumes") or []):
            stacks_map[key]["volumes"].add(vn)

        # Enriched container summary inside stack (A: ports/health/restart/mounts)
        rt = c.get("runtime") or {}
        stacks_map[key]["containers"].append(
            {
                "id": c["id"],
                "name": c["name"],
                "status": c["status"],
                "image": c["image"],
                "published_ports": rt.get("published_ports") or [],
                "health": rt.get("health"),
                "restart_policy": rt.get("restart_policy"),
                "mounts": rt.get("mounts") or {"bind_mounts": [], "volume_mounts": []},
            }
        )

    stacks = list(stacks_map.values())

    # Deterministic ordering and set conversion
    stacks.sort(key=lambda s: (s["kind"], s["name"]))
    for s in stacks:
        s["containers"].sort(key=lambda x: x.get("name") or "")
        s["networks"] = sorted(list(s["networks"]))
        s["volumes"] = sorted(list(s["volumes"]))

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
