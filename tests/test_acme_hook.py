"""Run the VPS renewal hook with isolated files and fake service commands."""

import importlib.util
import json
import stat
import subprocess
from pathlib import Path
from typing import Any

import pytest


@pytest.fixture()
def hook(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Any:
    source = Path(__file__).resolve().parents[1] / "ansible/files/bypass_cert_deploy.py"
    spec = importlib.util.spec_from_file_location("bypass_cert_deploy", source)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    for name in ("CONFIG", "STATE"):
        monkeypatch.setattr(module, name, tmp_path / name.lower())
    monkeypatch.setattr(module, "LIVE", tmp_path / "live")
    monkeypatch.setattr(module, "DEST", tmp_path / "certs")
    lineage = module.LIVE / "bypass-vpn.example.com"
    lineage.mkdir(parents=True)
    (lineage / "fullchain.pem").write_bytes(b"renewed certificate")
    (lineage / "privkey.pem").write_bytes(b"renewed private key")
    module.CONFIG.write_text(json.dumps({"domain": "vpn.example.com", "runtime": "native"}))
    monkeypatch.setenv("RENEWED_LINEAGE", str(lineage))
    return module


@pytest.mark.parametrize("runtime", ["native", "docker"])
def test_renewal_copies_certificate_and_restarts_only_active_consumers(
    hook: Any, monkeypatch: pytest.MonkeyPatch, runtime: str
) -> None:
    hook.CONFIG.write_text(json.dumps({"domain": "vpn.example.com", "runtime": runtime}))
    calls: list[list[str]] = []

    def run(command: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        calls.append(command)
        if command[:2] == ["systemctl", "is-active"]:
            return subprocess.CompletedProcess(command, 0 if "hysteria" in command[-1] else 3)
        if command[:2] == ["docker", "inspect"]:
            running = "true" if "hysteria" in command[-1] else "false"
            return subprocess.CompletedProcess(command, 0, running)
        return subprocess.CompletedProcess(command, 0)

    monkeypatch.setattr(hook.subprocess, "run", run)
    hook.deploy()
    assert (hook.DEST / "fullchain.pem").read_bytes() == b"renewed certificate"
    assert (hook.DEST / "privkey.pem").read_bytes() == b"renewed private key"
    assert stat.S_IMODE((hook.DEST / "privkey.pem").stat().st_mode) == 0o600
    restarts = [command for command in calls if "restart" in command]
    assert len(restarts) == 1 and "hysteria" in restarts[0][-1]
    assert not any("xray" in arg for command in calls for arg in command)
    calls.clear()
    hook.deploy()
    assert not calls  # An unchanged certificate does not restart services.
    (hook.LIVE / "bypass-vpn.example.com/fullchain.pem").write_bytes(b"next certificate")
    hook.deploy()
    assert (hook.DEST / "fullchain.pem").read_bytes() == b"next certificate"
    assert len([command for command in calls if "restart" in command]) == 1


@pytest.mark.parametrize("reason", ["manual", "other-domain", "no-lineage"])
def test_stale_renewal_cannot_overwrite_manual_or_different_certificate(
    hook: Any, monkeypatch: pytest.MonkeyPatch, reason: str
) -> None:
    if reason == "manual":
        hook.CONFIG.unlink()
    elif reason == "other-domain":
        monkeypatch.setenv("RENEWED_LINEAGE", str(hook.LIVE / "old-domain"))
    else:
        monkeypatch.delenv("RENEWED_LINEAGE")
    hook.deploy()
    assert not hook.DEST.exists()
    assert not hook.STATE.exists()


def test_failed_restart_is_retried_after_files_were_already_copied(
    hook: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    def fail_restart(command: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        if "restart" in command:
            raise subprocess.CalledProcessError(1, command)
        return subprocess.CompletedProcess(command, 0)

    monkeypatch.setattr(hook.subprocess, "run", fail_restart)
    with pytest.raises(subprocess.CalledProcessError):
        hook.deploy()
    assert not hook.STATE.exists()
    with pytest.raises(subprocess.CalledProcessError):
        hook.deploy()
    monkeypatch.setattr(
        hook.subprocess, "run", lambda command, **kwargs: subprocess.CompletedProcess(command, 0)
    )
    hook.deploy()
    assert hook.STATE.exists()
