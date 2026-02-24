# toonamiaftermath-downlink

> Lightweight IPTV feed generation service that builds M3U/XMLTV outputs and serves a Toonami-themed web control panel.
> Status: `Production` (actively maintained)

![CI](https://github.com/zachyzissou/toonamiaftermath-downlink/actions/workflows/baseline-python-ci.yml/badge.svg?branch=main)
![License](https://img.shields.io/github/license/zachyzissou/toonamiaftermath-downlink)
![Security](https://img.shields.io/badge/security-SECURITY.md-green)

## Overview

`toonamiaftermath-downlink` is a mixed Python + Node utility service for generating and serving IPTV artifacts.
Python handles channel ingestion and processing logic, while Node tooling supports linting and frontend asset checks.
The app can run locally or as a lightweight container with persistent data storage and scheduled updates.

## Problem / value

- **Problem:** Manual channel feed generation and schedule tracking is error-prone and difficult to observe.
- **Value:** This service automates updates, exposes status APIs, and provides an operator-facing web panel with diagnostics.
- **Users:** Home media operators, IPTV consumers, and maintainers managing containerized deployment.

## Architecture

```text
Cron/File trigger --> Python CLI wrapper (run_dev.py)
    --> toonamiaftermath-cli (external provider) --> parser/updaters --> feed assets
    --> Web API/Frontend --> clients (/m3u, /xmltv, /credentials)
    --> Health + diagnostics endpoints
```

## Features

- ✅ Auto-generates M3U and XMLTV with scheduled refresh.
- ✅ Provides Xtreme Codes-compatible API endpoints.
- ✅ Web UI for credentials/status and troubleshooting.
- ✅ Docker-first deployment and data persistence via mounted data volume.
- ✅ Multi-format testing suite (logic/integration/frontend) and lint stack.
- ⏳ Planned: stronger artifact integrity checks and richer runtime dashboards.

## Tech Stack

- Runtime: Python 3.12, Node.js 20
- Framework: custom Python service layer + browser UI assets
- Tooling: npm, ruff, black, python scripts, Play-ready Docker entrypoints
- CI/CD: GitHub Actions (`.github/workflows/`)
- Storage: mounted `/data` for generated artifacts/credentials

## Prerequisites

- Node.js 20.x (for linting/frontend checks)
- Python 3.11+ and pip
- Docker (for containerized build/run)
- Optional: external feed credentials available for your deployment environment

## Installation

```bash
git clone https://github.com/zachyzissou/toonamiaftermath-downlink.git
cd toonamiaftermath-downlink
python -m pip install -r requirements.txt
npm ci
```

## Configuration

| Key | Required | Default | Notes |
| --- | --- | --- | --- |
| `CRON_SCHEDULE` | no | `0 3 * * *` | Cron schedule for refresh jobs |
| `PORT` | no | `7004` | Public bind port |
| `DATA_DIR` | no | `/data` | Directory for generated assets |
| `LOG_LEVEL` | no | `info` | Operational log verbosity |
| `TOONAMI_AFTERMATH_CLI` | no | bundled value | Override CLI path/command |

## Usage

```bash
# Local one-shot app start
python run_dev.py
```

```bash
# Containerized run
docker build -t toonami-downlink:latest .
docker run -d --name toonami-downlink -p 7004:7004 -v ./data:/data toonami-downlink:latest
```

```bash
# Check service health
curl http://localhost:7004/health
```

```text
{"status":"ok","version":"1.0.0","artifacts":"m3u xml"}
```

## Testing & quality

```bash
python -m pip install -r requirements.txt
python test_logic.py
python test_integration.py
python test_frontend.py
npm run lint:python
npm run lint:js
```

## Security

- Report issues via [SECURITY.md](./SECURITY.md).
- Do not commit credentials, tokens, or generated user secrets in VCS.
- Protect `main` with PR review and CI checks.
- Container artifacts and generated files in `/data` should remain write-protected outside deployment owner.

## Contributing

1. Branch from `main` and scope changes to a single area.
2. Run lint and all three test entrypoints before PR.
3. Update `README.md` sections if behavior changes.
4. Add evidence in PR description using the provided PR template checklist.

## Deployment / runbook

- Default target in this repo is containerized deployment.
- Rollback: stop new container and redeploy known-good image tag.
- Emergency: remove schedule trigger and run manual startup with explicit CLI logs if upstream feed behavior changes.

## Troubleshooting

- **Health endpoint fails**: check container logs and `DATA_DIR` write permissions.
- **Feed files stale**: verify scheduler (`CRON_SCHEDULE`) and rerun update routines manually.
- **No WebUI credentials shown**: clear old `/data/credentials.json` only if intentionally rotating, then restart.
- **`docker build` fails**: inspect Dockerfile stage for dependency or checksum mismatches.

## Observability

- Health and status endpoints are the primary runtime checks.
- Runtime logs expose refresh cycles and endpoint generation outcomes.
- `TROUBLESHOOTING.md` and `AUDIT.md` contain operational notes and history.
- CI publishes test and security artifacts where configured.

## Roadmap

- Add stricter API response contract checks for `/player_api.php` and `/get.php`.
- Expand monitoring dashboards and webhook alerts for missed update windows.
- Improve automated smoke coverage for container restart behaviors.

## Known risks

- Dependence on external Toonami Aftermath feed availability.
- Feed schema changes can require parser updates.
- Scheduling drift across host clocks can skip or double-run updates.

## Release notes / changelog

- This baseline PR updates governance docs, bug report templates, CODEOWNERS, and CI baseline checks.
- No runtime behavior or payload format change is included.

## License & contact

- License: MIT (`LICENSE`)
- Maintainer: `@zachyzissou`
- Security: see [SECURITY.md](./SECURITY.md)
