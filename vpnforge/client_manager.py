"""CRUD over Client entries inside a Secrets document.

Rules (from TZ §2, §4.5):
  * sub_token / vless_uuid / hysteria_user / hysteria_pass are generated
    once on client creation and never regenerated implicitly.
  * label is unique within a secrets file.
  * disabled=True excludes the client from configs and subscription,
    but the entry stays in the file (so re-enabling keeps identity).
  * rotate_all: snapshot current secrets, then regenerate every
    client-bound secret (uuid / hysteria creds / sub_token), keeping
    labels and client ids. Reality/Hysteria server keys and all other
    secrets fields are preserved.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone

from vpnforge import crypto_utils
from vpnforge.models import Client, Secrets
from vpnforge.secrets_store import SecretsStore

logger = logging.getLogger(__name__)


class ClientError(Exception):
    """Base class for client_manager errors."""


class ClientNotFound(ClientError):
    """Raised when a client id is not present in the secrets file."""


class ClientConflict(ClientError):
    """Raised on uniqueness violations (e.g. duplicate label)."""


class ClientManager:
    """Mutates Client entries inside a Secrets document via SecretsStore."""

    def __init__(self, store: SecretsStore) -> None:
        self._store = store

    # ---------- read ----------

    def list_clients(self, ip: str) -> list[Client]:
        return list(self._store.load(ip).clients)

    def get_client(self, ip: str, client_id: str) -> Client:
        secrets = self._store.load(ip)
        return self._find(secrets, client_id)

    # ---------- write ----------

    def add_client(self, ip: str, label: str) -> Client:
        label = label.strip()
        if not label:
            raise ClientError("label must not be empty")

        secrets = self._store.load(ip)
        self._assert_label_unique(secrets, label, ignore_id=None)

        client = self._make_client(label=label)
        secrets.clients.append(client)
        self._store.save(secrets)
        logger.info("Added client %s (%s) to %s", client.id, client.label, ip)
        return client

    def remove_client(self, ip: str, client_id: str) -> None:
        secrets = self._store.load(ip)
        before = len(secrets.clients)
        secrets.clients = [c for c in secrets.clients if c.id != client_id]
        if len(secrets.clients) == before:
            raise ClientNotFound(f"client {client_id!r} not found for {ip}")
        self._store.save(secrets)
        logger.info("Removed client %s from %s", client_id, ip)

    def rename_client(self, ip: str, client_id: str, label: str) -> Client:
        label = label.strip()
        if not label:
            raise ClientError("label must not be empty")

        secrets = self._store.load(ip)
        self._assert_label_unique(secrets, label, ignore_id=client_id)

        target = self._find(secrets, client_id)
        target.label = label
        self._store.save(secrets)
        logger.info("Renamed client %s -> %s on %s", client_id, label, ip)
        return target

    def disable_client(self, ip: str, client_id: str) -> Client:
        secrets = self._store.load(ip)
        target = self._find(secrets, client_id)
        target.disabled = True
        self._store.save(secrets)
        logger.info("Disabled client %s on %s", client_id, ip)
        return target

    def enable_client(self, ip: str, client_id: str) -> Client:
        secrets = self._store.load(ip)
        target = self._find(secrets, client_id)
        target.disabled = False
        self._store.save(secrets)
        logger.info("Enabled client %s on %s", client_id, ip)
        return target

    def rotate_all(self, ip: str) -> list[Client]:
        """Regenerate all client-bound secrets, keeping ids and labels.

        Reality/Hysteria server keys, domain, protocols, cloudflare state
        and cert info are preserved. A snapshot of the pre-rotation file
        is written to <root>/_archive/.
        """
        snapshot_path = self._store.snapshot(ip, tag="rotate")
        logger.info("Snapshot before rotate_all for %s: %s", ip, snapshot_path)

        secrets = self._store.load(ip)
        now = datetime.now(timezone.utc)

        for c in secrets.clients:
            c.vless_uuid = crypto_utils.generate_uuid4()
            c.hysteria_user = _user_from_label(c.label)
            c.hysteria_pass = crypto_utils.generate_password(32)
            c.sub_token = crypto_utils.generate_sub_token()
            # keep c.id, c.label, c.created_at, c.disabled
            _ = now  # reserved for future use if we add rotated_at

        self._store.save(secrets)
        logger.info("Rotated %d clients for %s", len(secrets.clients), ip)
        return list(secrets.clients)

    # ---------- internals ----------

    def _find(self, secrets: Secrets, client_id: str) -> Client:
        for c in secrets.clients:
            if c.id == client_id:
                return c
        raise ClientNotFound(f"client {client_id!r} not found")

    def _assert_label_unique(
        self, secrets: Secrets, label: str, *, ignore_id: str | None
    ) -> None:
        needle = label.lower()
        for c in secrets.clients:
            if c.id == ignore_id:
                continue
            if c.label.lower() == needle:
                raise ClientConflict(f"label {label!r} already in use")

    def _make_client(self, *, label: str) -> Client:
        return Client(
            id=crypto_utils.generate_uuid4(),
            label=label,
            sub_token=crypto_utils.generate_sub_token(),
            vless_uuid=crypto_utils.generate_uuid4(),
            hysteria_user=_user_from_label(label),
            hysteria_pass=crypto_utils.generate_password(32),
            disabled=False,
        )


def _user_from_label(label: str) -> str:
    """Derive a Hysteria username from a label.

    Hysteria 2 userpass expects a printable ASCII name. We normalize the
    label to lowercase ASCII alnum + '-' and fall back to a random token
    if nothing usable remains (e.g. fully cyrillic labels).
    """
    translit = _translit_ru(label)
    out = "".join(ch if ch.isalnum() and ch.isascii() else "-" for ch in translit.lower())
    out = "-".join(filter(None, out.split("-")))
    if not out:
        return "u" + crypto_utils.generate_sub_token()[:8]
    return out[:32]


_RU_MAP = {
    "а": "a", "б": "b", "в": "v", "г": "g", "д": "d", "е": "e", "ё": "e",
    "ж": "zh", "з": "z", "и": "i", "й": "y", "к": "k", "л": "l", "м": "m",
    "н": "n", "о": "o", "п": "p", "р": "r", "с": "s", "т": "t", "у": "u",
    "ф": "f", "х": "h", "ц": "c", "ч": "ch", "ш": "sh", "щ": "sch",
    "ъ": "", "ы": "y", "ь": "", "э": "e", "ю": "yu", "я": "ya",
}


def _translit_ru(s: str) -> str:
    return "".join(_RU_MAP.get(ch, ch) for ch in s)