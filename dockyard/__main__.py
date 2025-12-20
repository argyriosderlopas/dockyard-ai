#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import sys
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Any

from internal.scanner.docker_scan import scan_docker_environment
from internal.analyzer.analyze_snapshot import analyze_snapshot


def _default_snapshot_dir() -> Path:
    env = os.environ.get("DOCKYARD_SNAPSHOT_DIR")
    if env:
        return Path(env).expanduser().resolve()
    return (Path.home() / "homelab" / "dockyard-ai" / "snapshots").resolve()


def _find_latest_snapshot(snapshot_dir: Path) -> Optional[Path]:
    if not snapshot_dir.exists():
        return None
    cands = sorted(snapshot_dir.glob("dockyard_*.json"), key=lambda p: p.stat().st_mtime, reverse=True)
    return cands[0] if cands else None


def _write_latest_pointer(repo_root: Path, snap_path: Path) -> None:
    target = repo_root / "dockyard_snapshot_latest.json"
    try:
        target.write_text(snap_path.read_text(encoding="utf-8"), encoding="utf-8")
    except Exception:
        return


def _write_latest_analysis(repo_root: Path, report: dict) -> None:
    target = repo_root / "dockyard_analysis_latest.json"
    try:
        target.write_text(json.dumps(report, indent=2, sort_keys=False) + "\n", encoding="utf-8")
    except Exception:
        return


def _maybe_relocate_snapshot(snap_path: Path, output_dir: Path) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)

    try:
        src_parent = snap_path.parent.resolve()
        dst_parent = output_dir.resolve()
    except Exception:
        src_parent = snap_path.parent
        dst_parent = output_dir

    if src_parent == dst_parent:
        return snap_path

    dst_path = output_dir / snap_path.name
    shutil.copy2(snap_path, dst_path)
    return dst_path


def _utc_stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")


def _extract_path_from_scan_result(scan_result: Any) -> Optional[Path]:
    if scan_result is None:
        return None

    if isinstance(scan_result, (str, os.PathLike)):
        return Path(scan_result).expanduser()

    if isinstance(scan_result, dict):
        candidate_keys = (
            "snapshot_path",
            "snap_path",
            "output_path",
            "path",
            "written_path",
            "wrote_snapshot",
            "file",
        )
        for k in candidate_keys:
            v = scan_result.get(k)
            if isinstance(v, (str, os.PathLike)) and str(v).strip():
                return Path(v).expanduser()

    return None


def _write_snapshot_payload(output_dir: Path, payload: dict) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    snap_path = output_dir / f"dockyard_{_utc_stamp()}.json"
    snap_path.write_text(json.dumps(payload, indent=2, sort_keys=False) + "\n", encoding="utf-8")
    os.chmod(snap_path, 0o644)
    return snap_path


def _safe_write_line(text: str, *, stream) -> None:
    try:
        stream.write(text + "\n")
    except BrokenPipeError:
        raise SystemExit(0)


def _safe_print(text: str = "") -> None:
    _safe_write_line(text, stream=sys.stdout)


def _safe_eprint(text: str = "") -> None:
    _safe_write_line(text, stream=sys.stderr)


def cmd_scan(args: argparse.Namespace) -> int:
    out_dir = Path(args.output_dir).expanduser().resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    scan_result = scan_docker_environment()

    written_path = _extract_path_from_scan_result(scan_result)
    if written_path is not None and written_path.exists():
        snap_path = _maybe_relocate_snapshot(written_path, out_dir)
    else:
        if not isinstance(scan_result, dict):
            raise RuntimeError("scan_docker_environment() returned neither a snapshot path nor a snapshot dict payload.")
        snap_path = _write_snapshot_payload(out_dir, scan_result)

    if args.write_latest:
        repo_root = Path(__file__).resolve().parents[1]
        _write_latest_pointer(repo_root=repo_root, snap_path=snap_path)

    _safe_print(f"Wrote snapshot: {snap_path}")
    return 0


def cmd_analyze(args: argparse.Namespace) -> int:
    snapshot_path: Optional[Path] = None
    if args.snapshot:
        snapshot_path = Path(args.snapshot).expanduser().resolve()

    snapshot_dir = Path(args.snapshot_dir).expanduser().resolve()

    if snapshot_path is None:
        snapshot_path = _find_latest_snapshot(snapshot_dir)
        if snapshot_path is None:
            _safe_eprint(f"No snapshots found under: {snapshot_dir}")
            return 2

    if not snapshot_path.exists():
        _safe_eprint(f"Snapshot not found: {snapshot_path}")
        return 2

    report = analyze_snapshot(
        snapshot_path=snapshot_path,
        fail_on=args.fail_on,
    )

    if args.format == "json":
        _safe_print(json.dumps(report, indent=2, sort_keys=False))
    else:
        _safe_print(f"Snapshot: {snapshot_path}")
        _safe_print(f"Scanned at: {report.get('scanned_at')}")
        s = report.get("summary", {})
        _safe_print(
            "Summary:"
            f" stacks={s.get('stacks_total', 0)}"
            f" containers={s.get('containers_total', 0)}"
            f" exposed_stacks={s.get('stacks_exposed', 0)}"
            f" docker_sock_stacks={s.get('stacks_with_docker_sock', 0)}"
            f" host_network_stacks={s.get('stacks_with_host_network', 0)}"
        )

        counts = (s.get("findings_by_severity") or {})
        if counts:
            _safe_print(
                "Findings:"
                f" critical={counts.get('critical', 0)}"
                f" high={counts.get('high', 0)}"
                f" medium={counts.get('medium', 0)}"
                f" low={counts.get('low', 0)}"
            )

        _safe_print("")
        _safe_print("Top risks:")
        for row in report.get("top_risks", [])[: args.top]:
            name = (row.get("stack") or {}).get("name")
            flags = ",".join(row.get("risk_flags", []))
            score = row.get("risk_score", 0)
            _safe_print(f"  - {name}: score={score} flags=[{flags}] findings={len(row.get('findings', []))}")

    if args.output:
        out_path = Path(args.output).expanduser().resolve()
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(report, indent=2, sort_keys=False) + "\n", encoding="utf-8")
        _safe_print("")
        _safe_print(f"Wrote analysis: {out_path}")

    if args.write_latest:
        repo_root = Path(__file__).resolve().parents[1]
        _write_latest_analysis(repo_root=repo_root, report=report)

    fail_meta = report.get("policy") or {}
    return int(fail_meta.get("exit_code", 0))


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="dockyard", description="Dockyard-AI: scan Docker, then analyze snapshots.")
    sub = p.add_subparsers(dest="cmd", required=True)

    scan = sub.add_parser("scan", help="Capture a Docker snapshot JSON.")
    scan.add_argument("--output-dir", default=str(_default_snapshot_dir()), help="Directory to write snapshots.")
    scan.add_argument(
        "--write-latest",
        action="store_true",
        help="Write a copy of the latest snapshot to ./dockyard_snapshot_latest.json",
    )
    scan.set_defaults(func=cmd_scan)

    analyze = sub.add_parser("analyze", help="Analyze a snapshot JSON (no Docker calls).")
    analyze.add_argument("--snapshot", default="", help="Path to a snapshot JSON. If empty, uses latest in snapshot-dir.")
    analyze.add_argument("--snapshot-dir", default=str(_default_snapshot_dir()), help="Directory to look for snapshots.")
    analyze.add_argument("--format", choices=["text", "json"], default="text", help="Output format.")
    analyze.add_argument("--top", type=int, default=10, help="Top N risky stacks to show in text format.")
    analyze.add_argument("--output", default="", help="Write full analysis JSON to this path.")
    analyze.add_argument(
        "--write-latest",
        action="store_true",
        help="Write a copy of the latest analysis report to ./dockyard_analysis_latest.json",
    )
    analyze.add_argument(
        "--fail-on",
        choices=["none", "low", "medium", "high", "critical"],
        default="none",
        help="Exit non-zero if any finding severity is >= threshold (useful for CI).",
    )
    analyze.set_defaults(func=cmd_analyze)

    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
