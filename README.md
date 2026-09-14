# VPN-Forge (backend)

Local FastAPI app that deploys a VPN stack (Hysteria 2, VLESS Reality xHTTP, OpenFlux) to a clean Ubuntu VPS via Ansible. Control plane stays on your machine; the VPS only runs protocol daemons and a tiny subscription server on port 80.

This repo is **backend-only** (no UI).

## Requirements

- Python 3.11+
- [Poetry](https://python-poetry.org/)
- Ansible (`ansible-playbook` on PATH, e.g. `pipx install ansible-core`)
- SSH access to the target VPS (key or password)

## Install

```bash
poetry install
cp .env.example .env
```

Environment (`VPNFORGE_` prefix):

| Variable | Default | Meaning |
|---|---|---|
| `VPNFORGE_DATA_DIR` | `./data` | Secrets and deploy run dirs |
| `VPNFORGE_LOG_LEVEL` | `INFO` | Log level |
| `VPNFORGE_ANSIBLE_BIN` | `ansible-playbook` | Playbook binary |
| `VPNFORGE_ANSIBLE_TIMEOUT` | `1800` | Deploy timeout, seconds |
| `VPNFORGE_CF_API_TOKEN` | empty | Cloudflare API token (DNS A upsert) |

Secrets live in `data/secrets/<ip>.json` (mode `600`) and are gitignored.

## Run

```bash
poetry run uvicorn vpnforge.main:app --host 127.0.0.1 --port 8000
```

`GET /api/health` should return `{"status":"ok"}`.

Main routes: cert validate, DNS upsert, secrets load/export/import, clients CRUD + rotate, `POST /api/deploy` (202 + `job_id`), `GET /api/deploy/stream/{job_id}` (SSE), local `GET /api/sub/{token}`.

`POST /api/deploy` is `multipart/form-data`:

- `payload` — JSON `DeployRequest` (ip, protocols, domain, ssh, openflux, …)
- `fullchain` / `privkey` — PEM files, required when Hysteria 2 is enabled

At least one protocol must be enabled. Reality / Hysteria keys are generated once and reused on redeploy.

## Tests

```bash
poetry run pytest
poetry run ruff check
poetry run mypy vpnforge
```

Coverage gate is 85%. Tests do not talk to the network (Cloudflare and Ansible are mocked).

## Limitations (this iteration)

- No UI, QR codes, ACME issuance, Xray gRPC stats, or multi-server.
- Certificates are uploaded; they are not issued on the VPS.
- OpenFlux `raw` mode does not configure iptables for you.
- Windows-specific ansible-runner behaviour is not supported.
- E2E against a real VPS is manual: valid cert + CF token + clean Ubuntu → deploy → `curl http://<vps>/sub/<token>`.
