from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


ANALYSIS_SCHEMA_VERSION = "analysis.v1"


_SEVERITY_ORDER: Dict[str, int] = {
    "none": 0,
    "low": 10,
    "medium": 20,
    "high": 30,
    "critical": 40,
}


@dataclass(frozen=True)
class Finding:
    code: str
    severity: str
    title: str
    evidence: Dict[str, Any]

    def as_dict(self) -> dict:
        return {
            "code": self.code,
            "severity": self.severity,
            "title": self.title,
            "evidence": self.evidence,
        }


def _load_snapshot(snapshot_path: Path) -> dict:
    raw = snapshot_path.read_text(encoding="utf-8")
    data = json.loads(raw)
    if not isinstance(data, dict):
        raise ValueError("Snapshot JSON must be a JSON object.")
    return data


def _get(obj: dict, path: List[str], default=None):
    cur = obj
    for p in path:
        if not isinstance(cur, dict):
            return default
        cur = cur.get(p)
    return cur if cur is not None else default


def _normalize_containers(snapshot: dict) -> List[dict]:
    containers = _get(snapshot, ["docker", "containers"], default=[])
    if not isinstance(containers, list):
        return []
    out: List[dict] = []
    for c in containers:
        if isinstance(c, dict):
            out.append(c)
    out.sort(key=lambda x: (str(x.get("name") or ""), str(x.get("id") or "")))
    return out


def _stack_id_from_container(c: dict) -> Tuple[str, str]:
    stk = c.get("stack") if isinstance(c.get("stack"), dict) else {}
    kind = (stk.get("kind") or "ungrouped").strip()
    name = (stk.get("name") or "ungrouped").strip()
    if not kind:
        kind = "ungrouped"
    if not name:
        name = "ungrouped"
    return (kind, name)


def _service_name_for_container(c: dict) -> str:
    compose = c.get("compose") if isinstance(c.get("compose"), dict) else None
    if compose and compose.get("service"):
        return str(compose.get("service"))
    name = c.get("name")
    return str(name) if name else "unknown"


def _published_ports(c: dict) -> List[dict]:
    runtime = c.get("runtime") if isinstance(c.get("runtime"), dict) else {}
    ports = runtime.get("published_ports")
    if not isinstance(ports, list):
        return []
    out: List[dict] = []
    for p in ports:
        if isinstance(p, dict):
            out.append(p)
    return out


def _container_flags(c: dict) -> Dict[str, bool]:
    runtime = c.get("runtime") if isinstance(c.get("runtime"), dict) else {}
    exposed = bool(runtime.get("exposed"))
    docker_sock = bool(runtime.get("docker_sock"))
    host_network = bool(runtime.get("host_network"))
    return {"exposed": exposed, "docker_sock": docker_sock, "host_network": host_network}


def _container_networks(c: dict) -> List[str]:
    nets = c.get("networks")
    if not isinstance(nets, list):
        return []
    return sorted([str(x) for x in nets if x is not None])


def _container_bind_paths(c: dict) -> List[str]:
    runtime = c.get("runtime") if isinstance(c.get("runtime"), dict) else {}
    paths = runtime.get("bind_paths")
    if not isinstance(paths, list):
        return []
    return sorted([str(x) for x in paths if x is not None])


def _container_restart_policy(c: dict) -> Optional[str]:
    runtime = c.get("runtime") if isinstance(c.get("runtime"), dict) else {}
    rp = runtime.get("restart_policy")
    if rp is None:
        return None
    s = str(rp).strip()
    return s if s else None


def _container_status(c: dict) -> str:
    st = c.get("status")
    return str(st) if st is not None else ""


def _container_health(c: dict) -> Optional[str]:
    runtime = c.get("runtime") if isinstance(c.get("runtime"), dict) else {}
    h = runtime.get("health")
    if h is None:
        return None
    s = str(h).strip()
    return s if s else None


def _findings_for_stack(containers: List[dict]) -> List[Finding]:
    findings: List[Finding] = []

    any_host = any(_container_flags(c).get("host_network") for c in containers)
    if any_host:
        ev = {"networks": ["host"]}
        findings.append(
            Finding(
                code="host_network",
                severity="high",
                title="Stack uses host networking",
                evidence=ev,
            )
        )

    any_sock = any(_container_flags(c).get("docker_sock") for c in containers)
    if any_sock:
        sock_containers = sorted([str(c.get("name") or "") for c in containers if _container_flags(c).get("docker_sock")])
        findings.append(
            Finding(
                code="docker_sock",
                severity="critical",
                title="Stack mounts the Docker socket (root-equivalent access)",
                evidence={"containers": sock_containers, "path": "/var/run/docker.sock"},
            )
        )

    exposed = []
    for c in containers:
        for p in _published_ports(c):
            exposed.append(
                {
                    "container": c.get("name"),
                    "host_ip": p.get("host_ip"),
                    "host_port": p.get("host_port"),
                    "container_port": p.get("container_port"),
                }
            )
    if exposed:
        exposed.sort(
            key=lambda x: (
                str(x.get("host_port") or ""),
                str(x.get("host_ip") or ""),
                str(x.get("container") or ""),
                str(x.get("container_port") or ""),
            )
        )
        findings.append(
            Finding(
                code="published_ports",
                severity="medium",
                title="Stack publishes ports to the host",
                evidence={"ports": exposed[:50], "ports_count": len(exposed)},
            )
        )

    # Operational hygiene signals (useful, low severity)
    unhealthy = []
    for c in containers:
        h = _container_health(c)
        if h and h.lower() not in ("healthy",):
            unhealthy.append({"container": c.get("name"), "health": h})
    if unhealthy:
        findings.append(
            Finding(
                code="unhealthy",
                severity="low",
                title="One or more containers report unhealthy or unknown health status",
                evidence={"containers": unhealthy},
            )
        )

    no_restart = []
    for c in containers:
        rp = _container_restart_policy(c)
        if not rp or rp == "no":
            status = _container_status(c).lower()
            # Ignore exited containers for this signal unless they are supposed to be long-running.
            if status in ("running", "restarting"):
                no_restart.append({"container": c.get("name"), "restart_policy": rp or "none"})
    if no_restart:
        findings.append(
            Finding(
                code="no_restart_policy",
                severity="low",
                title="One or more running containers have no restart policy",
                evidence={"containers": no_restart},
            )
        )

    # Broad bind-mount signal (can be risky, but depends on context)
    bind_paths = sorted({p for c in containers for p in _container_bind_paths(c)})
    if bind_paths:
        findings.append(
            Finding(
                code="bind_mounts",
                severity="low",
                title="Stack uses bind mounts (review host path exposure)",
                evidence={"bind_paths": bind_paths[:80], "bind_paths_count": len(bind_paths)},
            )
        )

    return findings


def _risk_flags_from_findings(findings: List[Finding]) -> List[str]:
    codes = {f.code for f in findings}
    out: List[str] = []
    if "docker_sock" in codes:
        out.append("docker_sock")
    if "host_network" in codes:
        out.append("host_network")
    if "published_ports" in codes:
        out.append("published_ports")
    return out


def _risk_score(findings: List[Finding]) -> int:
    # Deterministic score used for sorting. Higher is worse.
    # Weight by severity and by common “blast radius” signals.
    weights = {
        "critical": 90,
        "high": 45,
        "medium": 25,
        "low": 5,
    }
    score = 0
    for f in findings:
        score += int(weights.get(f.severity, 0))
        # Nudge common high-impact codes
        if f.code == "docker_sock":
            score += 25
        if f.code == "host_network":
            score += 10
        if f.code == "published_ports":
            ports_count = int((f.evidence or {}).get("ports_count") or 0)
            score += min(30, ports_count * 2)
    return score


def _stack_exposure(stack_containers: List[dict]) -> List[dict]:
    exposure: List[dict] = []
    for c in stack_containers:
        for p in _published_ports(c):
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
            str(x.get("host_port") or ""),
            str(x.get("host_ip") or ""),
            str(x.get("container") or ""),
            str(x.get("container_port") or ""),
        )
    )
    return exposure


def _services_breakdown(stack_containers: List[dict]) -> Dict[str, int]:
    out: Dict[str, int] = {}
    for c in stack_containers:
        svc = _service_name_for_container(c)
        out[svc] = out.get(svc, 0) + 1
    return dict(sorted(out.items(), key=lambda kv: (kv[0], kv[1])))


def _findings_by_severity(stacks: List[dict]) -> Dict[str, int]:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for s in stacks:
        for f in (s.get("findings") or []):
            if not isinstance(f, dict):
                continue
            sev = str(f.get("severity") or "").lower()
            if sev in counts:
                counts[sev] += 1
    return counts


def _policy_eval(stacks: List[dict], fail_on: str) -> dict:
    threshold = _SEVERITY_ORDER.get((fail_on or "none").lower(), 0)
    worst = 0
    worst_label = "none"

    for s in stacks:
        for f in (s.get("findings") or []):
            if not isinstance(f, dict):
                continue
            sev = str(f.get("severity") or "none").lower()
            sev_score = _SEVERITY_ORDER.get(sev, 0)
            if sev_score > worst:
                worst = sev_score
                worst_label = sev

    failed = worst >= threshold and threshold > 0
    exit_code = 3 if failed else 0

    return {
        "fail_on": (fail_on or "none").lower(),
        "threshold": threshold,
        "worst_severity": worst_label,
        "failed": failed,
        "exit_code": exit_code,
    }


def analyze_snapshot(snapshot_path: Path, fail_on: str = "none") -> dict:
    sp = Path(snapshot_path).expanduser().resolve()
    snapshot = _load_snapshot(sp)

    input_schema_version = str(snapshot.get("schema_version") or "")
    scanned_at = snapshot.get("scanned_at")

    containers = _normalize_containers(snapshot)

    stacks_map: Dict[Tuple[str, str], List[dict]] = {}
    for c in containers:
        sid = _stack_id_from_container(c)
        stacks_map.setdefault(sid, []).append(c)

    stacks_out: List[dict] = []
    for (kind, name), stack_containers in sorted(stacks_map.items(), key=lambda kv: (kv[0][0], kv[0][1])):
        findings = _findings_for_stack(stack_containers)
        flags = _risk_flags_from_findings(findings)

        stacks_out.append(
            {
                "stack": {"kind": kind, "name": name},
                "services": _services_breakdown(stack_containers),
                "risk_flags": flags,
                "exposure": _stack_exposure(stack_containers),
                "risk_score": _risk_score(findings),
                "findings": [f.as_dict() for f in findings],
            }
        )

    stacks_total = len(stacks_out)
    containers_total = len(containers)

    stacks_exposed = sum(1 for s in stacks_out if "published_ports" in (s.get("risk_flags") or []))
    stacks_with_docker_sock = sum(1 for s in stacks_out if "docker_sock" in (s.get("risk_flags") or []))
    stacks_with_host_network = sum(1 for s in stacks_out if "host_network" in (s.get("risk_flags") or []))

    top_risks = sorted(stacks_out, key=lambda s: int(s.get("risk_score") or 0), reverse=True)

    summary = {
        "stacks_total": stacks_total,
        "containers_total": containers_total,
        "stacks_exposed": stacks_exposed,
        "stacks_with_docker_sock": stacks_with_docker_sock,
        "stacks_with_host_network": stacks_with_host_network,
        "findings_by_severity": _findings_by_severity(stacks_out),
    }

    policy = _policy_eval(stacks_out, fail_on=fail_on)

    report = {
        "schema_version": ANALYSIS_SCHEMA_VERSION,
        "input_schema_version": input_schema_version,
        "scanned_at": scanned_at,
        "snapshot_path": str(sp),
        "summary": summary,
        "stacks": stacks_out,
        "top_risks": top_risks,
        "policy": policy,
    }

    return report
