# internal/scanner/docker_scan.py

import copy
from datetime import datetime

import docker

from internal.models.schema import BASE_SCHEMA


def _labels_from_container_attrs(attrs: dict) -> dict:
    return (attrs.get("Config") or {}).get("Labels") or {}


def _labels_from_resource_attrs(attrs: dict) -> dict:
    return attrs.get("Labels") or {}


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


def _container_mounts(attrs: dict) -> dict:
    """
    Summarize mounts into:
      - bind_mounts: [{"source","destination","rw"}]
      - volume_mounts: [{"name","destination","rw"}]
      - bind_sources: ["/path", ...]
      - volume_names: ["vol1", ...]
    """
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


def _container_named_volumes(attrs: dict) -> list[str]:
    # Backward compatible view used elsewhere
    return _container_mounts(attrs).get("volume_names", [])


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
    """
    Build a stable list of exposure entries per stack:
      {"container": "name", "host_ip": "...", "host_port": "...", "container_port": "..."}
    """
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
    exposure.sort(key=lambda x: (x.get("host_port") or "", x.get("host_ip") or "", x.get("container") or "", x.get("container_port") or ""))
    return exposure


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

        labels = _labels_from_container_attrs(attrs)
        kind, stack_name = _stack_key(labels)

        c_networks = _container_networks(attrs)

        published_ports = _container_published_ports(attrs)
        health = _container_health(attrs)
        restart_policy = _container_restart_policy(attrs)
        mounts = _container_mounts(attrs)

        flags = _runtime_flags(c_networks, mounts, published_ports)
        risk_flags = _risk_flags(flags)

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
                "volumes": _container_named_volumes(attrs),
                "runtime": {
                    "published_ports": published_ports,
                    "health": health,
                    "restart_policy": restart_policy,
                    "exit_code": _container_exit_code(attrs),
                    "started_at": _container_started_at(attrs),
                    "finished_at": _container_finished_at(attrs),
                    "mounts": {
                        "bind_mounts": mounts.get("bind_mounts") or [],
                        "volume_mounts": mounts.get("volume_mounts") or [],
                    },
                    # A+: flags and rollups
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

    # ----------------------------
    # Volumes (include label-based stack hint when present)
    # ----------------------------
    volumes = []
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
                # A+: stack rollups
                "exposure": [],
                "risk_flags": set(),
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

        # Enriched container summary inside stack
        rt = c.get("runtime") or {}
        container_summary = {
            "id": c["id"],
            "name": c["name"],
            "status": c["status"],
            "image": c["image"],
            "published_ports": rt.get("published_ports") or [],
            "health": rt.get("health"),
            "restart_policy": rt.get("restart_policy"),
            "exit_code": rt.get("exit_code"),
            "started_at": rt.get("started_at"),
            "finished_at": rt.get("finished_at"),
            "mounts": rt.get("mounts") or {"bind_mounts": [], "volume_mounts": []},
            # A+: flags
            "exposed": rt.get("exposed"),
            "docker_sock": rt.get("docker_sock"),
            "host_network": rt.get("host_network"),
            "bind_paths": rt.get("bind_paths") or [],
            "volume_names": rt.get("volume_names") or [],
            "risk_flags": rt.get("risk_flags") or [],
        }
        stacks_map[key]["containers"].append(container_summary)

        # A+: stack rollups
        for rf in (rt.get("risk_flags") or []):
            stacks_map[key]["risk_flags"].add(rf)

    stacks = list(stacks_map.values())

    # Deterministic ordering and set conversion + stack rollups
    stacks.sort(key=lambda s: (s["kind"], s["name"]))
    for s in stacks:
        s["containers"].sort(key=lambda x: x.get("name") or "")
        s["networks"] = sorted(list(s["networks"]))
        s["volumes"] = sorted(list(s["volumes"]))

        # Exposure rollup from stack container summaries
        s["exposure"] = _stack_exposure_from_containers(s["containers"])

        # Risk flags rollup
        s["risk_flags"] = sorted(list(s["risk_flags"]))

        # Keep meta tidy
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
