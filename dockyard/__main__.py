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
from internal.reporter.explain_analysis import render_explain_report


def _default_snapshot_dir() -> Path:
    env = os.environ.get("DOCKYARD_SNAPSHOT_DIR")
    if env:
        return Path(env).expanduser().resolve()
    return (Path.home() / "homelab" / "dockyard-ai" / "snapshots").resolve()


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _default_latest_snapshot_pointer() -> Path:
    return _repo_root() / "dockyard_snapshot_latest.json"


def _default_latest_analysis_pointer() -> Path:
    return _repo_root() / "dockyard_analysis_latest.json"


def _find_latest_snapshot(snapshot_dir: Path) -> Optional[Path]:
    if not snapshot_dir.exists():
        return None
    cands = sorted(snapshot_dir.glob("dockyard_*.json"), key=lambda p: p.stat().st_mtime, reverse=True)
    return cands[0] if cands else None


def _write_latest_pointer(target_file: Path, source_json_file: Path) -> None:
    try:
        target_file.write_text(source_json_file.read_text(encoding="utf-8"), encoding="utf-8")
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


def _safe_print_json(obj: Any) -> None:
    """
    Prevent BrokenPipeError when piping JSON to tools like `head`.
    """
    try:
        sys.stdout.write(json.dumps(obj, indent=2, sort_keys=False) + "\n")
        sys.stdout.flush()
    except BrokenPipeError:
        try:
            sys.stdout.close()
        except Exception:
            pass
        raise SystemExit(0)


def cmd_scan(args: argparse.Namespace) -> int:
    out_dir = Path(args.output_dir).expanduser().resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    scan_result = scan_docker_environment()

    written_path = _extract_path_from_scan_result(scan_result)
    if written_path is not None and written_path.exists():
        snap_path = _maybe_relocate_snapshot(written_path, out_dir)
    else:
        if not isinstance(scan_result, dict):
            raise RuntimeError(
                "scan_docker_environment() returned neither a snapshot path nor a snapshot dict payload."
            )
        snap_path = _write_snapshot_payload(out_dir, scan_result)

    if args.write_latest:
        _write_latest_pointer(_default_latest_snapshot_pointer(), snap_path)

    print(f"Wrote snapshot: {snap_path}")
    return 0


def cmd_analyze(args: argparse.Namespace) -> int:
    snapshot_path: Optional[Path] = None
    if args.snapshot:
        snapshot_path = Path(args.snapshot).expanduser().resolve()

    snapshot_dir = Path(args.snapshot_dir).expanduser().resolve()

    if snapshot_path is None:
        snapshot_path = _find_latest_snapshot(snapshot_dir)
        if snapshot_path is None:
            print(f"No snapshots found under: {snapshot_dir}", file=sys.stderr)
            return 2

    if not snapshot_path.exists():
        print(f"Snapshot not found: {snapshot_path}", file=sys.stderr)
        return 2

    report = analyze_snapshot(snapshot_path=snapshot_path)

    if args.write_latest:
        # This expects analyze_snapshot() to include a snapshot_path, scanned_at, etc.
        out_path = _default_latest_analysis_pointer()
        try:
            out_path.write_text(json.dumps(report, indent=2, sort_keys=False) + "\n", encoding="utf-8")
        except Exception as e:
            print(f"Failed to write latest analysis pointer: {out_path} ({e})", file=sys.stderr)

    if args.format == "json":
        _safe_print_json(report)
    else:
        print(f"Snapshot: {snapshot_path}")
        print(f"Scanned at: {report.get('scanned_at')}")
        s = report.get("summary", {})
        print(
            "Summary:"
            f" stacks={s.get('stacks_total', 0)}"
            f" containers={s.get('containers_total', 0)}"
            f" exposed_stacks={s.get('stacks_exposed', 0)}"
            f" docker_sock_stacks={s.get('stacks_with_docker_sock', 0)}"
            f" host_network_stacks={s.get('stacks_with_host_network', 0)}"
        )
        fb = (s.get("findings_by_severity") or {})
        if fb:
            print(
                "Findings:"
                f" critical={fb.get('critical', 0)}"
                f" high={fb.get('high', 0)}"
                f" medium={fb.get('medium', 0)}"
                f" low={fb.get('low', 0)}"
            )

        print("\nTop risks:")
        for row in report.get("top_risks", [])[: args.top]:
            name = (row.get("stack") or {}).get("name")
            flags = ",".join(row.get("risk_flags", []))
            score = row.get("risk_score", 0)
            print(f"  - {name}: score={score} flags=[{flags}] findings={len(row.get('findings', []))}")

    if args.output:
        out_path = Path(args.output).expanduser().resolve()
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(report, indent=2, sort_keys=False) + "\n", encoding="utf-8")
        print(f"\nWrote analysis: {out_path}")

    # Policy exit behavior (if present in report)
    pol = report.get("policy") or {}
    exit_code = pol.get("exit_code")
    if isinstance(exit_code, int):
        return exit_code

    return 0


def cmd_explain(args: argparse.Namespace) -> int:
    analysis_path: Optional[Path] = None
    if args.analysis:
        analysis_path = Path(args.analysis).expanduser().resolve()
    else:
        # Default to repository pointer produced by `analyze --write-latest`
        candidate = _default_latest_analysis_pointer()
        if candidate.exists():
            analysis_path = candidate

    if analysis_path is None or not analysis_path.exists():
        print(
            "No analysis JSON found.\n"
            "Run:\n"
            "  python -m dockyard analyze --write-latest\n"
            "Or pass an explicit file:\n"
            "  python -m dockyard explain --analysis /path/to/analysis.json",
            file=sys.stderr,
        )
        return 2

    report = json.loads(analysis_path.read_text(encoding="utf-8"))

    if args.format == "json":
        explained = render_explain_report(
            analysis=report,
            min_severity=args.min_severity,
            limit=args.limit,
            include_evidence=args.include_evidence,
        )
        _safe_print_json(explained)
        return 0

    text = render_explain_report(
        analysis=report,
        min_severity=args.min_severity,
        limit=args.limit,
        include_evidence=args.include_evidence,
        as_text=True,
    )
    sys.stdout.write(text)
    return 0


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
        help="Write a copy of the latest analysis to ./dockyard_analysis_latest.json",
    )
    analyze.set_defaults(func=cmd_analyze)

    explain = sub.add_parser("explain", help="Explain why the analysis fails a policy threshold.")
    explain.add_argument(
        "--analysis",
        default="",
        help="Path to an analysis JSON. If empty, uses ./dockyard_analysis_latest.json",
    )
    explain.add_argument(
        "--min-severity",
        choices=["low", "medium", "high", "critical"],
        default="high",
        help="Show findings at or above this severity.",
    )
    explain.add_argument(
        "--limit",
        type=int,
        default=200,
        help="Maximum number of findings to print.",
    )
    explain.add_argument(
        "--include-evidence",
        action="store_true",
        help="Include a compact evidence snippet per finding.",
    )
    explain.add_argument("--format", choices=["text", "json"], default="text", help="Output format.")
    explain.set_defaults(func=cmd_explain)

    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
