#!/usr/bin/python3
"""Certbot deploy hook. Runs on the VPS using only Python's standard library."""

import hashlib
import json
import os
import subprocess
import tempfile
from pathlib import Path

CONFIG = Path("/etc/vpnforge/acme.json")
LIVE = Path("/etc/letsencrypt/live")
DEST = Path("/etc/vpnforge/certs")
STATE = Path("/etc/vpnforge/acme-deployed.sha256")


def atomic_write(path: Path, content: bytes, mode: int) -> None:
    descriptor, temporary = tempfile.mkstemp(prefix=".bypass-", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as target:
            os.fchmod(target.fileno(), mode)
            target.write(content)
            target.flush()
            os.fsync(target.fileno())
        os.replace(temporary, path)
    finally:
        Path(temporary).unlink(missing_ok=True)


def deploy() -> None:
    # Removing this file disables the hook when switching to manual certificates.
    if not CONFIG.exists():
        return
    config = json.loads(CONFIG.read_text())
    expected = LIVE / ("bypass-" + config["domain"])
    lineage = os.environ.get("RENEWED_LINEAGE")
    if not lineage or Path(lineage).resolve() != expected.resolve():
        return
    fullchain = (expected / "fullchain.pem").read_bytes()
    private_key = (expected / "privkey.pem").read_bytes()
    signature = hashlib.sha256(
        fullchain + private_key + json.dumps(config, sort_keys=True).encode()
    ).hexdigest().encode()
    DEST.mkdir(mode=0o755, parents=True, exist_ok=True)
    changed = False
    for name, content, mode in [
        ("fullchain.pem", fullchain, 0o644), ("privkey.pem", private_key, 0o600)
    ]:
        target = DEST / name
        if not target.exists() or target.read_bytes() != content:
            atomic_write(target, content, mode)
            changed = True
        else:
            target.chmod(mode)
    if not changed and STATE.exists() and STATE.read_bytes() == signature:
        print("Certificate unchanged")
        return
    if config["runtime"] == "docker":
        for container in ("vpnforge-hysteria", "vpnforge-sub"):
            result = subprocess.run(
                ["docker", "inspect", "--format", "{{.State.Running}}", container],
                capture_output=True, text=True, check=False,
            )
            if result.returncode == 0 and result.stdout.strip() == "true":
                subprocess.run(["docker", "restart", container], check=True)
    else:
        for unit in ("vpnforge-hysteria.service", "vpnforge-sub.service"):
            result = subprocess.run(
                ["systemctl", "is-active", "--quiet", unit], check=False,
            )
            if result.returncode == 0:
                subprocess.run(["systemctl", "restart", unit], check=True)
    # Persist only after successful restarts, allowing a retry after failure.
    atomic_write(STATE, signature, 0o600)
    print("Certificate deployed")


if __name__ == "__main__":
    deploy()
