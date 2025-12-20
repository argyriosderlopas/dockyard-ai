# dockyard-ai

Dockyard-AI is a local-first Docker inventory scanner and snapshot analyzer.

It is designed to be published on GitHub as a reproducible, CLI-driven tool:
- `scan` connects to the local Docker daemon and writes a JSON snapshot.
- `analyze` reads a snapshot and prints a deterministic risk summary.

## Repository layout
dockyard/
init.py
main.py
internal/
init.py
models/
init.py
schema.py
scanner/
init.py
docker_scan.py
README.md
requirements.txt
Makefile

## Requirements

- Linux host with Docker installed and running
- Python 3.12+ recommended (tested with Python 3.12)
- Permission to access Docker (root or user in the `docker` group)

## Install

### Using Makefile

```bash
make install
