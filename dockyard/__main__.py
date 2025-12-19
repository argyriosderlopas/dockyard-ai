import json
import sys

from internal.scanner.docker_scan import scan_docker_environment


def main():
    try:
        data = scan_docker_environment()
        print(json.dumps(data, indent=2))
        return 0
    except Exception as e:
        print(str(e), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
