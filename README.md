# dockyard-ai

Dockyard AI is a local-first CLI tool that inspects a running Docker environment
and produces a structured, machine-readable snapshot of what is actually running.

It is designed for developers and operators who inherit Docker hosts
without context, documentation, or ownership history.

## What it does (today)

Dockyard AI connects to the local Docker engine and extracts:

- Containers (running and stopped)
- Images
- Networks
- Volumes

The output is a single deterministic JSON document describing the environment
at a specific point in time.

No inference. No modification. No orchestration.

## What it does not do

- It does not deploy containers
- It does not manage Docker
- It does not replace Portainer
- It does not call any AI service
- It does not require internet access

## Why it exists

Most Docker environments fail not because of technology,
but because context is lost.

Dockyard AI exists to recover that context.

## Installation

Requirements:
- Python 3.9+
- Docker Engine running locally
- Access to the Docker socket

Install dependency:

```bash
pip install docker

