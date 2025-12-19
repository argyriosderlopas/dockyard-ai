# dockyard/__main__.py
import argparse
import json
import signal
import sys
from pathlib import Path

from internal.scanner.docker_scan import scan_docker_environment

DEFAULT_SNAPSHOT_DIR = Path("/home/aderlopas/homelab/dockyard-ai/snapshots")


def write_snapshot(data: dict, out_dir: Path) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)

    scanned_at = (data.get("scanned_at") or "").strip()
    # filename-safe timestamp: remove separators that break filenames or sorting
    ts = (
        scanned_at.replace(":", "")
        .replace("-", "")
        .replace(".", "")
        .replace("Z", "Z")
    )
    if not ts:
        ts = "snapshot"

    path = out_dir / f"dockyard_{ts}.json"
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    return path


def main() -> int:
    # When piping to tools like `head`, the consumer closes stdout early.
    # This prevents noisy BrokenPipeError tracebacks on Linux.
    try:
        signal.signal(signal.SIGPIPE, signal.SIG_DFL)
    except Exception:
        # Non-POSIX environments or restricted signal handling
        pass

    parser = argparse.ArgumentParser(prog="dockyard", add_help=True)
    parser.add_argument(
        "--output",
        action="store_true",
        help="Write a snapshot JSON file under /home/aderlopas/homelab/dockyard-ai/snapshots",
    )
    parser.add_argument(
        "--output-dir",
        default=str(DEFAULT_SNAPSHOT_DIR),
        help="Directory to write snapshots (default: /home/aderlopas/homelab/dockyard-ai/snapshots)",
    )
    args = parser.parse_args()

    try:
        data = scan_docker_environment()

        # Always print JSON to stdout
        try:
            sys.stdout.write(json.dumps(data, indent=2) + "\n")
            sys.stdout.flush()
        except BrokenPipeError:
            # Downstream closed pipe (e.g., `| head`). Exit quietly.
            try:
                sys.stdout.close()
            except Exception:
                pass
            return 0

        # Optionally write snapshot to disk
        if args.output:
            out_path = write_snapshot(data, Path(args.output_dir))
            print(f"Wrote snapshot: {out_path}", file=sys.stderr)

        return 0

    except Exception as e:
        print(str(e), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
