# internal/scanner/docker_scan.py

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

import copy
import docker

from internal.models.schema import BASE_SCHEMA


def _iso_utc_now_z() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _labels_from_container_attrs(attrs: dict) -> dict:
    return (attrs.get("Config") or {}).get("Labels") or {}


def _labels_from_resource_attrs(attrs: dict) -> dict:
    return attrs.get("Labels") or {}


def _stack_key(labels: dict) -> tuple[str, str]:
    if labels.get("com.docker.compose.project"):
        return ("compose", labels["com.docker.compose.project"])
    if labels.get("com.portainer.stack.name"):
        return ("portainer", labels["com.portainer.stack.name"])
    return ("ungrouped", "ungrouped")


def _container_networks(attrs: dict) -> list[str]:
    nets = ((attrs.get("NetworkSettings") or {}).get("Networks") or {})
    return sorted(list(nets.keys()))


def _container_mounts(attrs: dict) -> dict:
    mounts = attrs.get("Mounts") or []
    binds: list[dict] = []
    vols: list[dict] = []
    bind_sources: list[str] = []
    volume_names: list[str] = []

    for m in mounts:
        mtype = m.get("Type")
        dst = m.get("Destination")
        rw = m.get("RW")

        if mtype == "bind":
            src = m.get("Source")
            binds.append(
                {
                    "source": src,
                    "destination": dst,
                    "rw": bool(rw) if rw is not None else None,
                }
            )
            if src:
                bind_sources.append(src)

        elif mtype == "volume":
            nm = m.get("Name")
            vols.append(
                {
                    "name": nm,
                    "destination": dst,
                    "rw": bool(rw) if rw is not None else None,
                }
            )
            if nm:
                volume_names.append(nm)

    binds.sort(key=lambda x: (x.get("destination") or "", x.get("source") or ""))
    vols.sort(key=lambda x: (x.get("destination") or "", x.get("name") or ""))

    bind_sources = sorted(set(bind_sources))
    volume_names = sorted(set(volume_names))

    return {
        "bind_mounts": binds,
        "volume_mounts": vols,
        "bind_sources": bind_sources,
        "volume_names": volume_names,
    }


def _container_published_ports(attrs: dict) -> list[dict]:
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


def _container_exit_code(attrs: dict) -> int | None:
    state = attrs.get("State") or {}
    code = state.get("ExitCode")
    return code if isinstance(code, int) else None


def _container_started_at(attrs: dict) -> str | None:
    state = attrs.get("State") or {}
    return state.get("StartedAt")


def _container_finished_at(attrs: dict) -> str | None:
    state = attrs.get("State") or {}
    return state.get("FinishedAt")


def _runtime_flags(networks: list[str], mounts: dict, published_ports: list[dict]) -> dict:
    bind_sources = mounts.get("bind_sources") or []
    docker_sock = any(src == "/var/run/docker.sock" for src in bind_sources)
    host_network = "host" in (networks or [])
    exposed = bool(published_ports)

    return {
        "exposed": exposed,
        "docker_sock": docker_sock,
        "host_network": host_network,
        "bind_paths": bind_sources,
        "volume_names": mounts.get("volume_names") or [],
    }


def _risk_flags(flags: dict) -> list[str]:
    out: list[str] = []
    if flags.get("docker_sock"):
        out.append("docker_sock")
    if flags.get("host_network"):
        out.append("host_network")
    if flags.get("exposed"):
        out.append("published_ports")
    return out


def _stack_exposure_from_containers(stack_containers: list[dict]) -> list[dict]:
    exposure: list[dict] = []
    for c in stack_containers:
        for p in (c.get("published_ports") or []):
            exposure.append(
                {
                    "container": c.get("name"),
                    "host_ip": p.get("host_ip"),
                    "host_port": p.get("host_port"),
                    "container_port": p.get("container_port"),
                }
            )
    exposure.sort(
        key=lambda x: (
            x.get("host_port") or "",
            x.get("host_ip") or "",
            x.get("container") or "",
            x.get("container_port") or "",
        )
    )
    return exposure


def _safe_list_image_tags(image_obj: Any) -> list[str]:
    try:
        tags = getattr(image_obj, "tags", None)
        if isinstance(tags, list):
            return [str(t) for t in tags if str(t).strip()]
    except Exception:
        pass
    return []


def scan_docker_environment() -> dict:
    try:
        client = docker.from_env()
        client.ping()
    except Exception as e:
        raise RuntimeError(f"Docker is not accessible from this host: {e}")

    payload = copy.deepcopy(BASE_SCHEMA)
    payload["scanned_at"] = _iso_utc_now_z()

    # ----------------------------
    # Containers
    # ----------------------------
    containers: list[dict] = []
    for c in client.containers.list(all=True):
        attrs = c.attrs or {}
        created = attrs.get("Created")

        labels = _labels_from_container_attrs(attrs)
        kind, stack_name = _stack_key(labels)

        c_networks = _container_networks(attrs)
        published_ports = _container_published_ports(attrs)
        mounts = _container_mounts(attrs)

        flags = _runtime_flags(c_networks, mounts, published_ports)
        risk_flags = _risk_flags(flags)

        compose_project = labels.get("com.docker.compose.project")

        containers.append(
            {
                "id": c.id,
                "name": c.name,
                "image": _safe_list_image_tags(c.image),
                "status": c.status,
                "created": created,
                "stack": {"kind": kind, "name": stack_name},
                "compose": (
                    {
                        "project": compose_project,
                        "service": labels.get("com.docker.compose.service"),
                        "working_dir": labels.get("com.docker.compose.project.working_dir"),
                        "config_files": labels.get("com.docker.compose.project.config_files"),
                    }
                    if compose_project
                    else None
                ),
                "networks": c_networks,
                "volumes": mounts.get("volume_names") or [],
                "runtime": {
                    "published_ports": published_ports,
                    "health": _container_health(attrs),
                    "restart_policy": _container_restart_policy(attrs),
                    "exit_code": _container_exit_code(attrs),
                    "started_at": _container_started_at(attrs),
                    "finished_at": _container_finished_at(attrs),
                    "mounts": {
                        "bind_mounts": mounts.get("bind_mounts") or [],
                        "volume_mounts": mounts.get("volume_mounts") or [],
                    },
                    "exposed": flags.get("exposed"),
                    "docker_sock": flags.get("docker_sock"),
                    "host_network": flags.get("host_network"),
                    "bind_paths": flags.get("bind_paths") or [],
                    "volume_names": flags.get("volume_names") or [],
                    "risk_flags": risk_flags,
                },
            }
        )

    containers.sort(key=lambda x: x.get("name") or "")
    payload["docker"]["containers"] = containers

    # ----------------------------
    # Images
    # ----------------------------
    images: list[dict] = []
    for i in client.images.list():
        attrs = i.attrs or {}
        tags = i.tags if isinstance(i.tags, list) else []
        images.append({"id": i.id, "tags": tags, "size": attrs.get("Size")})
    images.sort(key=lambda x: (",".join(x.get("tags") or []), x.get("id") or ""))
    payload["docker"]["images"] = images

    # ----------------------------
    # Networks
    # ----------------------------
    networks: list[dict] = []
    for n in client.networks.list():
        attrs = n.attrs or {}
        nlabels = _labels_from_resource_attrs(attrs)
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
    payload["docker"]["networks"] = networks

    # ----------------------------
    # Volumes
    # ----------------------------
    volumes: list[dict] = []
    for v in client.volumes.list():
        attrs = v.attrs or {}
        vlabels = _labels_from_resource_attrs(attrs)
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
    payload["docker"]["volumes"] = volumes

    # ----------------------------
    # Stacks (derived from containers, deterministic)
    # ----------------------------
    stacks_map: dict[tuple[str, str], dict] = {}
    for c in containers:
        sk = c.get("stack") or {}
        kind = sk.get("kind") or "ungrouped"
        name = sk.get("name") or "ungrouped"
        key = (str(kind), str(name))

        if key not in stacks_map:
            stacks_map[key] = {
                "kind": key[0],
                "name": key[1],
                "meta": None,
                "containers": [],
                "services": {},
                "networks": [],
                "volumes": [],
                "exposure": [],
                "risk_flags": [],
            }

        stacks_map[key]["containers"].append(c)

    stacks_out: list[dict] = []
    for (kind, name), st in sorted(stacks_map.items(), key=lambda kv: (kv[0][0], kv[0][1])):
        stack_containers = st["containers"]
        stack_containers.sort(key=lambda x: x.get("name") or "")

        # Meta (only for compose, from first container with compose info)
        meta = None
        if kind == "compose":
            for c in stack_containers:
                comp = c.get("compose")
                if isinstance(comp, dict) and comp.get("project"):
                    meta = {
                        "compose": {
                            "project": comp.get("project"),
                            "working_dir": comp.get("working_dir"),
                            "config_files": comp.get("config_files"),
                        }
                    }
                    break

        # Services
        services: dict[str, int] = {}
        if kind == "compose":
            for c in stack_containers:
                comp = c.get("compose") or {}
                svc = comp.get("service")
                if svc:
                    services[str(svc)] = services.get(str(svc), 0) + 1
        else:
            # For non-compose, use container names as a minimal stable listing (counted)
            for c in stack_containers:
                nm = c.get("name")
                if nm:
                    services[str(nm)] = services.get(str(nm), 0) + 1

        # Networks used by containers
        nets: set[str] = set()
        for c in stack_containers:
            for n in (c.get("networks") or []):
                if n:
                    nets.add(str(n))
        networks_list = sorted(nets)

        # Volume names used by containers
        vol_names: set[str] = set()
        for c in stack_containers:
            for vn in (c.get("runtime") or {}).get("volume_names", []):
                if vn:
                    vol_names.add(str(vn))
        volumes_list = sorted(vol_names)

        # Exposure
        exposure = _stack_exposure_from_containers(
            [
                {
                    "name": c.get("name"),
                    "published_ports": (c.get("runtime") or {}).get("published_ports") or [],
                }
                for c in stack_containers
            ]
        )

        # Risk flags union (from container runtime flags)
        rf: set[str] = set()
        for c in stack_containers:
            for f in ((c.get("runtime") or {}).get("risk_flags") or []):
                if f:
                    rf.add(str(f))
        risk_flags = sorted(rf)

        stacks_out.append(
            {
                "kind": kind,
                "name": name,
                "meta": meta,
                "containers": [
                    {
                        "id": c.get("id"),
                        "name": c.get("name"),
                        "status": c.get("status"),
                        "image": c.get("image") or [],
                        "published_ports": (c.get("runtime") or {}).get("published_ports") or [],
                        "health": (c.get("runtime") or {}).get("health"),
                        "restart_policy": (c.get("runtime") or {}).get("restart_policy"),
                        "exit_code": (c.get("runtime") or {}).get("exit_code"),
                        "started_at": (c.get("runtime") or {}).get("started_at"),
                        "finished_at": (c.get("runtime") or {}).get("finished_at"),
                        "mounts": (c.get("runtime") or {}).get("mounts") or {"bind_mounts": [], "volume_mounts": []},
                        "exposed": (c.get("runtime") or {}).get("exposed"),
                        "docker_sock": (c.get("runtime") or {}).get("docker_sock"),
                        "host_network": (c.get("runtime") or {}).get("host_network"),
                        "bind_paths": (c.get("runtime") or {}).get("bind_paths") or [],
                        "volume_names": (c.get("runtime") or {}).get("volume_names") or [],
                        "risk_flags": (c.get("runtime") or {}).get("risk_flags") or [],
                    }
                    for c in stack_containers
                ],
                "services": dict(sorted(services.items(), key=lambda kv: kv[0])),
                "networks": networks_list,
                "volumes": volumes_list,
                "exposure": exposure,
                "risk_flags": risk_flags,
            }
        )

    payload["docker"]["stacks"] = stacks_out
    return payload
