from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


@dataclass(frozen=True)
class Finding:
    code: str
    severity: str  # low | medium | high | critical
    title: str
    evidence: Dict[str, Any]


def _load_snapshot(snapshot_path: Path) -> Dict[str, Any]:
    d = json.loads(snapshot_path.read_text(encoding="utf-8"))
    if not isinstance(d, dict):
        raise ValueError("Snapshot root must be a JSON object.")
    return d


def _get_stacks(snapshot: Dict[str, Any]) -> List[Dict[str, Any]]:
    docker = snapshot.get("docker") or {}
    stacks = docker.get("stacks") or []
    if not isinstance(stacks, list):
        return []
    return [s for s in stacks if isinstance(s, dict)]


def _get_containers(snapshot: Dict[str, Any]) -> List[Dict[str, Any]]:
    docker = snapshot.get("docker") or {}
    containers = docker.get("containers") or []
    if not isinstance(containers, list):
        return []
    return [c for c in containers if isinstance(c, dict)]


def _risk_score_from_flags(flags: List[str]) -> int:
    # Deterministic and explainable. Tunable later.
    weights = {
        "docker_sock": 60,
        "host_network": 35,
        "published_ports": 25,
    }
    return int(sum(weights.get(f, 0) for f in flags))


def _normalize_host_ip(host_ip: str) -> str:
    # Standardize common representations.
    if host_ip in ("0.0.0.0", "::"):
        return host_ip
    return host_ip.strip()


def _is_world_bind(host_ip: str) -> bool:
    ip = _normalize_host_ip(host_ip)
    return ip in ("0.0.0.0", "::")


def _port_exposure_findings(exposure: List[Dict[str, Any]]) -> List[Finding]:
    findings: List[Finding] = []
    if not exposure:
        return findings

    world = [e for e in exposure if _is_world_bind(str(e.get("host_ip", "")))]
    if world:
        findings.append(
            Finding(
                code="published_ports_world",
                severity="high",
                title="Published ports bound to all interfaces",
                evidence={"exposure": world},
            )
        )

    # Identify likely-admin ports (heuristic, not claims).
    suspicious_ports = {"9000", "9443", "8200", "3000", "8080", "8081", "8083", "8085", "8088", "61208"}
    adminish = [e for e in exposure if str(e.get("host_port", "")) in suspicious_ports]
    if adminish:
        findings.append(
            Finding(
                code="published_ports_common_admin",
                severity="medium",
                title="Published ports include common admin/UI ports",
                evidence={"exposure": adminish},
            )
        )

    return findings


def _docker_sock_findings(stack: Dict[str, Any]) -> List[Finding]:
    findings: List[Finding] = []
    containers = stack.get("containers") or []
    if not isinstance(containers, list):
        return findings

    sock_mounts: List[Dict[str, Any]] = []
    for c in containers:
        if not isinstance(c, dict):
            continue
        mounts = ((c.get("mounts") or {}).get("bind_mounts") or []) if isinstance(c.get("mounts"), dict) else []
        for m in mounts:
            if not isinstance(m, dict):
                continue
            if str(m.get("source", "")) == "/var/run/docker.sock":
                sock_mounts.append(
                    {
                        "container": c.get("name"),
                        "rw": bool(m.get("rw", False)),
                        "destination": m.get("destination"),
                    }
                )

    if sock_mounts:
        rw = [x for x in sock_mounts if x.get("rw") is True]
        sev = "critical" if rw else "high"
        findings.append(
            Finding(
                code="docker_socket_mount",
                severity=sev,
                title="Docker socket mounted into container(s)",
                evidence={"docker_sock_mounts": sock_mounts},
            )
        )

    return findings


def _host_network_findings(stack: Dict[str, Any]) -> List[Finding]:
    nets = stack.get("networks") or []
    if not isinstance(nets, list):
        return []
    if "host" in nets:
        return [
            Finding(
                code="host_network",
                severity="high",
                title="Stack uses host networking",
                evidence={"networks": nets},
            )
        ]
    return []


def _rw_bind_mount_findings(stack: Dict[str, Any]) -> List[Finding]:
    findings: List[Finding] = []
    containers = stack.get("containers") or []
    if not isinstance(containers, list):
        return findings

    rw_binds: List[Dict[str, Any]] = []
    for c in containers:
        if not isinstance(c, dict):
            continue
        mounts = c.get("mounts") or {}
        if not isinstance(mounts, dict):
            continue
        binds = mounts.get("bind_mounts") or []
        if not isinstance(binds, list):
            continue
        for b in binds:
            if not isinstance(b, dict):
                continue
            # Exclude docker.sock here (handled by dedicated finding)
            if str(b.get("source", "")) == "/var/run/docker.sock":
                continue
            if bool(b.get("rw", False)) is True:
                rw_binds.append(
                    {
                        "container": c.get("name"),
                        "source": b.get("source"),
                        "destination": b.get("destination"),
                    }
                )

    if rw_binds:
        findings.append(
            Finding(
                code="rw_bind_mounts",
                severity="medium",
                title="Writable bind mounts detected",
                evidence={"rw_bind_mounts": rw_binds},
            )
        )
    return findings


def _stack_findings(stack: Dict[str, Any]) -> List[Finding]:
    findings: List[Finding] = []
    exposure = stack.get("exposure") or []
    if isinstance(exposure, list):
        findings.extend(_port_exposure_findings(exposure))

    findings.extend(_docker_sock_findings(stack))
    findings.extend(_host_network_findings(stack))
    findings.extend(_rw_bind_mount_findings(stack))

    return findings


def _severity_rank(sev: str) -> int:
    order = {"low": 10, "medium": 20, "high": 30, "critical": 40}
    return int(order.get(sev, 0))


def analyze_snapshot(snapshot_path: Path) -> Dict[str, Any]:
    snap = _load_snapshot(snapshot_path)
    stacks = _get_stacks(snap)
    containers = _get_containers(snap)

    analyzed: List[Dict[str, Any]] = []
    for s in stacks:
        risk_flags = s.get("risk_flags") or []
        if not isinstance(risk_flags, list):
            risk_flags = []

        exposure = s.get("exposure") or []
        if not isinstance(exposure, list):
            exposure = []

        findings = _stack_findings(s)

        score = _risk_score_from_flags([str(x) for x in risk_flags])
        # Findings add to the score in a bounded way (keeps flags as the primary axis).
        score += sum(_severity_rank(f.severity) for f in findings) // 4

        analyzed.append(
            {
                "stack": {"kind": s.get("kind"), "name": s.get("name")},
                "services": s.get("services") or {},
                "risk_flags": [str(x) for x in risk_flags],
                "exposure": exposure,
                "risk_score": int(score),
                "findings": [
                    {"code": f.code, "severity": f.severity, "title": f.title, "evidence": f.evidence} for f in findings
                ],
            }
        )

    # Summary (counts are factual, derived from snapshot only).
    stacks_exposed = sum(1 for x in analyzed if isinstance(x.get("exposure"), list) and len(x["exposure"]) > 0)
    stacks_sock = sum(1 for x in analyzed if "docker_sock" in (x.get("risk_flags") or []))
    stacks_hostnet = sum(1 for x in analyzed if "host_network" in (x.get("risk_flags") or []))

    # Sort top risks
    top_risks = sorted(analyzed, key=lambda x: int(x.get("risk_score", 0)), reverse=True)

    return {
        "schema_version": "analysis.v1",
        "input_schema_version": snap.get("schema_version"),
        "scanned_at": snap.get("scanned_at"),
        "snapshot_path": str(snapshot_path),
        "summary": {
            "stacks_total": len(stacks),
            "containers_total": len(containers),
            "stacks_exposed": int(stacks_exposed),
            "stacks_with_docker_sock": int(stacks_sock),
            "stacks_with_host_network": int(stacks_hostnet),
        },
        "stacks": analyzed,
        "top_risks": top_risks,
    }
