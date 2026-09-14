"""Atomic, file-per-IP store for Secrets documents.

Layout: <root>/<ip>.json, chmod 600, atomic write via tempfile + os.replace.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import tempfile
from contextlib import suppress
from datetime import UTC, datetime
from pathlib import Path

from pydantic import ValidationError

from vpnforge.models import Secrets

_IP_RE = re.compile(r"^[A-Za-z0-9._:\-]+$")


class SecretsError(Exception):
    """Base class for secrets_store errors."""


class SecretsNotFound(SecretsError):
    """Raised when a secrets file for the given IP does not exist."""


class SecretsInvalid(SecretsError):
    """Raised when JSON on disk cannot be parsed into Secrets."""


class SecretsStore:
    """Filesystem-backed store keyed by VPS IP/hostname."""

    def __init__(self, root: Path) -> None:
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        # Best-effort: directory itself only accessible to owner.
        with suppress(OSError):
            os.chmod(self.root, 0o700)

    # ---------- paths ----------

    def _path_for(self, ip: str) -> Path:
        if not ip or ip in {".", ".."} or not _IP_RE.match(ip):
            raise SecretsInvalid(f"invalid ip/host identifier: {ip!r}")
        return self.root / f"{ip}.json"

    # ---------- public API ----------

    def exists(self, ip: str) -> bool:
        return self._path_for(ip).is_file()

    def list_ips(self) -> list[str]:
        """Return IPs that have a secrets file (excludes archive)."""
        ips: list[str] = []
        if not self.root.is_dir():
            return ips
        for path in sorted(self.root.glob("*.json")):
            if path.name.startswith("."):
                continue
            ips.append(path.stem)
        return ips

    def load(self, ip: str) -> Secrets:
        path = self._path_for(ip)
        if not path.is_file():
            raise SecretsNotFound(f"secrets not found for {ip}")
        try:
            raw = path.read_text(encoding="utf-8")
        except OSError as exc:
            raise SecretsError(f"cannot read {path}: {exc}") from exc
        try:
            data = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise SecretsInvalid(f"invalid JSON in {path}: {exc}") from exc
        try:
            return Secrets.model_validate(data)
        except ValidationError as exc:
            raise SecretsInvalid(f"schema mismatch in {path}: {exc}") from exc

    def save(self, secrets: Secrets) -> None:
        secrets.updated_at = datetime.now(UTC)
        path = self._path_for(secrets.ip)

        payload = secrets.model_dump(mode="json")
        raw = json.dumps(payload, indent=2, ensure_ascii=False, sort_keys=False)

        tmp_fd, tmp_name = tempfile.mkstemp(
            prefix=f".{secrets.ip}.", suffix=".tmp", dir=self.root
        )
        tmp_path = Path(tmp_name)
        try:
            with os.fdopen(tmp_fd, "w", encoding="utf-8") as fh:
                fh.write(raw)
                fh.flush()
                os.fsync(fh.fileno())
            os.chmod(tmp_path, 0o600)
            os.replace(tmp_path, path)
        except Exception:
            tmp_path.unlink(missing_ok=True)
            raise

    def delete(self, ip: str) -> None:
        path = self._path_for(ip)
        if not path.is_file():
            raise SecretsNotFound(f"secrets not found for {ip}")
        path.unlink()

    def archive(self, ip: str) -> Path:
        """Move <ip>.json into <root>/_archive/<ip>.<ts>.json and return new path."""
        path = self._path_for(ip)
        if not path.is_file():
            raise SecretsNotFound(f"secrets not found for {ip}")

        archive_dir = self.root / "_archive"
        archive_dir.mkdir(parents=True, exist_ok=True)
        with suppress(OSError):
            os.chmod(archive_dir, 0o700)

        ts = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
        dest = archive_dir / f"{ip}.{ts}.json"
        shutil.move(str(path), str(dest))
        with suppress(OSError):
            os.chmod(dest, 0o600)
        return dest

    def export(self, ip: str) -> bytes:
        """Return the raw bytes of the secrets file (for download)."""
        path = self._path_for(ip)
        if not path.is_file():
            raise SecretsNotFound(f"secrets not found for {ip}")
        return path.read_bytes()

    def import_(self, ip: str, raw: bytes) -> Secrets:
        """Validate and persist external secrets bytes; returns parsed Secrets."""
        try:
            data = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise SecretsInvalid(f"invalid secrets payload: {exc}") from exc
        try:
            secrets = Secrets.model_validate(data)
        except ValidationError as exc:
            raise SecretsInvalid(f"schema mismatch in import: {exc}") from exc
        if secrets.ip != ip:
            raise SecretsInvalid(
                f"ip mismatch: payload is for {secrets.ip!r}, expected {ip!r}"
            )
        self.save(secrets)
        return secrets

    def snapshot(self, ip: str, *, tag: str = "") -> Path:
        """Copy <ip>.json into <root>/_archive/<ip>.<ts>[.<tag>].json.

        Unlike archive(), the live file stays in place.
        Returns the snapshot path.
        """
        path = self._path_for(ip)
        if not path.is_file():
            raise SecretsNotFound(f"secrets not found for {ip}")

        archive_dir = self.root / "_archive"
        archive_dir.mkdir(parents=True, exist_ok=True)
        with suppress(OSError):
            os.chmod(archive_dir, 0o700)

        ts = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
        suffix = f".{tag}" if tag else ""
        dest = archive_dir / f"{ip}.{ts}{suffix}.json"
        shutil.copy2(path, dest)
        with suppress(OSError):
            os.chmod(dest, 0o600)
        return dest
