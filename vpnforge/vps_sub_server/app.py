"""Subscription micro-backend served on a dedicated VPS port."""

from __future__ import annotations

import base64
import json
import os
import pathlib

from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse, PlainTextResponse

app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
CLIENTS_FILE = pathlib.Path(
    os.environ.get("VPNFORGE_CLIENTS_FILE", "/opt/vpnforge/sub/clients.json")
)


def _load_clients() -> dict[str, object]:
    try:
        raw = CLIENTS_FILE.read_text(encoding="utf-8")
    except OSError as exc:
        raise HTTPException(status_code=503, detail="clients file unavailable") from exc
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise HTTPException(status_code=503, detail="clients file invalid") from exc
    if not isinstance(data, dict):
        raise HTTPException(status_code=503, detail="clients file invalid")
    return data


@app.get("/sub/{token}", response_class=PlainTextResponse)
def get_sub(token: str) -> str:
    data = _load_clients()
    clients = data.get("clients")
    if not isinstance(clients, list):
        raise HTTPException(status_code=404, detail="not found")

    for entry in clients:
        if not isinstance(entry, dict):
            continue
        if entry.get("sub_token") != token:
            continue
        urls = entry.get("urls") or []
        if not isinstance(urls, list):
            urls = []
        lines = [str(u) for u in urls]
        payload = "\n".join(lines).encode("utf-8")
        return base64.b64encode(payload).decode("ascii")

    raise HTTPException(status_code=404, detail="not found")


@app.get("/config/{token}/xray.json", response_class=JSONResponse)
def get_xray_config(token: str) -> dict[str, object]:
    data = _load_clients()
    clients = data.get("clients")
    if not isinstance(clients, list):
        raise HTTPException(status_code=404, detail="not found")

    for entry in clients:
        if not isinstance(entry, dict) or entry.get("sub_token") != token:
            continue
        config = entry.get("xray_config")
        if isinstance(config, dict):
            return config
        raise HTTPException(status_code=404, detail="xray profile unavailable")

    raise HTTPException(status_code=404, detail="not found")


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}
