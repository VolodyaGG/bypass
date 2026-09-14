"""Tests for vpnforge.secrets_store."""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path

import pytest
from freezegun import freeze_time

from vpnforge.models import (
    Client,
    Hysteria2Config,
    ProtocolFlags,
    RealityConfig,
    Secrets,
)
from vpnforge.secrets_store import (
    SecretsInvalid,
    SecretsNotFound,
    SecretsStore,
)


def _make_secrets(ip: str = "1.2.3.4") -> Secrets:
    return Secrets(
        ip=ip,
        domain="node1.example.com",
        protocols=ProtocolFlags(hysteria2=True, vless_reality=True, openflux=False),
        reality=RealityConfig(
            private_key="PRIV",
            public_key="PUB",
            short_id="deadbeef",
        ),
        hysteria2=Hysteria2Config(obfs_password="obfs-pass"),
        clients=[
            Client(
                id="cid-1",
                label="Вася",
                sub_token="a" * 32,
                vless_uuid="11111111-1111-4111-8111-111111111111",
                hysteria_user="vasya",
                hysteria_pass="pass",
            )
        ],
    )


# ---------- exists / load ----------


def test_exists_false_when_missing(tmp_secrets_dir: Path) -> None:
    store = SecretsStore(tmp_secrets_dir)
    assert store.exists("1.2.3.4") is False


def test_load_raises_when_missing(tmp_secrets_dir: Path) -> None:
    store = SecretsStore(tmp_secrets_dir)
    with pytest.raises(SecretsNotFound):
        store.load("1.2.3.4")


# ---------- save / load roundtrip ----------


def test_roundtrip(tmp_secrets_dir: Path) -> None:
    store = SecretsStore(tmp_secrets_dir)
    s = _make_secrets()
    store.save(s)

    loaded = store.load("1.2.3.4")
    assert loaded.ip == s.ip
    assert loaded.domain == s.domain
    assert loaded.protocols.hysteria2 is True
    assert loaded.reality is not None and loaded.reality.short_id == "deadbeef"
    assert len(loaded.clients) == 1
    assert loaded.clients[0].label == "Вася"


def test_save_sets_updated_at(tmp_secrets_dir: Path) -> None:
    with freeze_time("2026-09-14T12:00:00Z") as frozen:
        store = SecretsStore(tmp_secrets_dir)
        s = _make_secrets()
        original_created = s.created_at
        store.save(s)
        assert s.created_at == original_created

        frozen.tick(60)
        s.domain = "other.example.com"
        store.save(s)

        loaded = store.load("1.2.3.4")
        assert loaded.updated_at > loaded.created_at


# ---------- permissions ----------


def test_file_permissions_600(tmp_secrets_dir: Path) -> None:
    store = SecretsStore(tmp_secrets_dir)
    store.save(_make_secrets())
    path = tmp_secrets_dir / "1.2.3.4.json"
    mode = stat.S_IMODE(path.stat().st_mode)
    assert mode == 0o600


def test_dir_permissions_700(tmp_secrets_dir: Path) -> None:
    SecretsStore(tmp_secrets_dir)
    mode = stat.S_IMODE(tmp_secrets_dir.stat().st_mode)
    assert mode == 0o700


# ---------- atomicity ----------


def test_save_is_atomic_no_partial_file(tmp_secrets_dir: Path) -> None:
    """No leftover *.tmp files after a successful save."""
    store = SecretsStore(tmp_secrets_dir)
    store.save(_make_secrets())
    leftovers = [p for p in tmp_secrets_dir.iterdir() if p.name.endswith(".tmp")]
    assert leftovers == []
    # also no dotfiles matching pattern
    assert not any(p.name.startswith(".1.2.3.4") for p in tmp_secrets_dir.iterdir())


def test_save_overwrites_existing(tmp_secrets_dir: Path) -> None:
    store = SecretsStore(tmp_secrets_dir)
    store.save(_make_secrets())
    s2 = _make_secrets()
    s2.domain = "changed.example.com"
    store.save(s2)
    loaded = store.load("1.2.3.4")
    assert loaded.domain == "changed.example.com"


# ---------- schema errors ----------


def test_load_invalid_json(tmp_secrets_dir: Path) -> None:
    (tmp_secrets_dir / "1.2.3.4.json").write_text("{not json", encoding="utf-8")
    store = SecretsStore(tmp_secrets_dir)
    with pytest.raises(SecretsInvalid):
        store.load("1.2.3.4")


def test_load_schema_mismatch(tmp_secrets_dir: Path) -> None:
    (tmp_secrets_dir / "1.2.3.4.json").write_text(
        json.dumps({"version": 1, "ip": 12345}), encoding="utf-8"
    )
    store = SecretsStore(tmp_secrets_dir)
    with pytest.raises(SecretsInvalid):
        store.load("1.2.3.4")


# ---------- ip validation ----------


@pytest.mark.parametrize("bad", ["", "../etc/passwd", "a/b", "with space", ".."])
def test_bad_ip_rejected(tmp_secrets_dir: Path, bad: str) -> None:
    store = SecretsStore(tmp_secrets_dir)
    with pytest.raises(SecretsInvalid):
        store.load(bad)


def test_hostname_allowed(tmp_secrets_dir: Path) -> None:
    store = SecretsStore(tmp_secrets_dir)
    s = _make_secrets(ip="node1.example.com")
    store.save(s)
    assert store.exists("node1.example.com")


# ---------- delete ----------


def test_delete(tmp_secrets_dir: Path) -> None:
    store = SecretsStore(tmp_secrets_dir)
    store.save(_make_secrets())
    store.delete("1.2.3.4")
    assert store.exists("1.2.3.4") is False


def test_delete_missing(tmp_secrets_dir: Path) -> None:
    store = SecretsStore(tmp_secrets_dir)
    with pytest.raises(SecretsNotFound):
        store.delete("1.2.3.4")


# ---------- archive ----------


def test_archive_moves_file(tmp_secrets_dir: Path) -> None:
    store = SecretsStore(tmp_secrets_dir)
    store.save(_make_secrets())

    with freeze_time("2026-09-14T12:00:00Z"):
        dest = store.archive("1.2.3.4")

    assert dest.exists()
    assert dest.parent.name == "_archive"
    assert dest.name.startswith("1.2.3.4.")
    assert dest.name.endswith(".json")
    assert not (tmp_secrets_dir / "1.2.3.4.json").exists()

    mode = stat.S_IMODE(dest.stat().st_mode)
    assert mode == 0o600


def test_archive_missing(tmp_secrets_dir: Path) -> None:
    store = SecretsStore(tmp_secrets_dir)
    with pytest.raises(SecretsNotFound):
        store.archive("1.2.3.4")


# ---------- export / import ----------


def test_export_returns_bytes(tmp_secrets_dir: Path) -> None:
    store = SecretsStore(tmp_secrets_dir)
    store.save(_make_secrets())
    raw = store.export("1.2.3.4")
    assert isinstance(raw, bytes)
    data = json.loads(raw)
    assert data["ip"] == "1.2.3.4"


def test_export_missing(tmp_secrets_dir: Path) -> None:
    store = SecretsStore(tmp_secrets_dir)
    with pytest.raises(SecretsNotFound):
        store.export("1.2.3.4")


def test_import_roundtrip(tmp_secrets_dir: Path) -> None:
    src = SecretsStore(tmp_secrets_dir / "src")
    src.save(_make_secrets())

    dst = SecretsStore(tmp_secrets_dir / "dst")
    raw = src.export("1.2.3.4")
    parsed = dst.import_("1.2.3.4", raw)
    assert parsed.ip == "1.2.3.4"
    assert dst.exists("1.2.3.4")


def test_import_invalid_json(tmp_secrets_dir: Path) -> None:
    store = SecretsStore(tmp_secrets_dir)
    with pytest.raises(SecretsInvalid):
        store.import_("1.2.3.4", b"{not json")


def test_import_ip_mismatch(tmp_secrets_dir: Path) -> None:
    store = SecretsStore(tmp_secrets_dir)
    store.save(_make_secrets(ip="1.2.3.4"))
    raw = store.export("1.2.3.4")
    with pytest.raises(SecretsInvalid, match="ip mismatch"):
        store.import_("5.6.7.8", raw)


# ---------- updated_at bump on every save ----------


def test_updated_at_bumps_on_second_save(tmp_secrets_dir: Path) -> None:
    store = SecretsStore(tmp_secrets_dir)
    with freeze_time("2026-09-14T12:00:00Z"):
        s = _make_secrets()
        store.save(s)
        first = s.updated_at
    with freeze_time("2026-09-14T12:05:00Z"):
        store.save(s)
        assert s.updated_at > first


def test_snapshot_keeps_live_file(tmp_secrets_dir: Path) -> None:
    store = SecretsStore(tmp_secrets_dir)
    store.save(_make_secrets())
    with freeze_time("2026-09-14T12:00:00Z"):
        dest = store.snapshot("1.2.3.4", tag="rotate")
    assert dest.exists()
    assert dest.name == "1.2.3.4.20260914T120000Z.rotate.json"
    assert (tmp_secrets_dir / "1.2.3.4.json").exists()
    mode = stat.S_IMODE(dest.stat().st_mode)
    assert mode == 0o600