"""Tests for vpnforge.client_manager."""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from vpnforge.client_manager import (
    ClientConflict,
    ClientError,
    ClientManager,
    ClientNotFound,
    _translit_ru,
    _user_from_label,
)
from vpnforge.models import ProtocolFlags, Secrets
from vpnforge.secrets_store import SecretsStore


@pytest.fixture()
def store(tmp_secrets_dir: Path) -> SecretsStore:
    s = SecretsStore(tmp_secrets_dir)
    s.save(Secrets(ip="1.2.3.4", protocols=ProtocolFlags(vless_reality=True)))
    return s


@pytest.fixture()
def mgr(store: SecretsStore) -> ClientManager:
    return ClientManager(store)


IP = "1.2.3.4"


# ---------- add ----------


def test_add_returns_client_with_generated_fields(mgr: ClientManager) -> None:
    c = mgr.add_client(IP, "Вася")
    assert c.label == "Вася"
    assert c.id
    assert re.fullmatch(r"[0-9a-f]{32}", c.sub_token)
    assert re.fullmatch(
        r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}",
        c.vless_uuid,
    )
    assert c.hysteria_user == "vasya"
    assert c.hysteria_pass
    assert c.disabled is False


def test_add_persists(mgr: ClientManager, store: SecretsStore) -> None:
    c = mgr.add_client(IP, "Вася")
    loaded = store.load(IP)
    assert len(loaded.clients) == 1
    assert loaded.clients[0].id == c.id


def test_add_empty_label(mgr: ClientManager) -> None:
    with pytest.raises(ClientError):
        mgr.add_client(IP, "   ")


def test_add_duplicate_label_case_insensitive(mgr: ClientManager) -> None:
    mgr.add_client(IP, "Вася")
    with pytest.raises(ClientConflict):
        mgr.add_client(IP, "вася")


def test_add_trims_label(mgr: ClientManager) -> None:
    c = mgr.add_client(IP, "  Вася  ")
    assert c.label == "Вася"


# ---------- list / get ----------


def test_list_empty(mgr: ClientManager) -> None:
    assert mgr.list_clients(IP) == []


def test_list_returns_all(mgr: ClientManager) -> None:
    mgr.add_client(IP, "A")
    mgr.add_client(IP, "B")
    labels = {c.label for c in mgr.list_clients(IP)}
    assert labels == {"A", "B"}


def test_get_found(mgr: ClientManager) -> None:
    c = mgr.add_client(IP, "Вася")
    assert mgr.get_client(IP, c.id).id == c.id


def test_get_missing(mgr: ClientManager) -> None:
    with pytest.raises(ClientNotFound):
        mgr.get_client(IP, "no-such")


# ---------- remove ----------


def test_remove(mgr: ClientManager) -> None:
    c = mgr.add_client(IP, "Вася")
    mgr.remove_client(IP, c.id)
    assert mgr.list_clients(IP) == []


def test_remove_missing(mgr: ClientManager) -> None:
    with pytest.raises(ClientNotFound):
        mgr.remove_client(IP, "no-such")


# ---------- rename ----------


def test_rename_ok(mgr: ClientManager) -> None:
    c = mgr.add_client(IP, "Вася")
    renamed = mgr.rename_client(IP, c.id, "Петя")
    assert renamed.label == "Петя"
    # hysteria_user не меняется при rename
    assert renamed.hysteria_user == "vasya"


def test_rename_empty(mgr: ClientManager) -> None:
    c = mgr.add_client(IP, "Вася")
    with pytest.raises(ClientError):
        mgr.rename_client(IP, c.id, "   ")


def test_rename_conflict(mgr: ClientManager) -> None:
    a = mgr.add_client(IP, "A")
    mgr.add_client(IP, "B")
    with pytest.raises(ClientConflict):
        mgr.rename_client(IP, a.id, "b")


def test_rename_same_label_ok(mgr: ClientManager) -> None:
    c = mgr.add_client(IP, "Вася")
    # переименование в себя же — не конфликт
    same = mgr.rename_client(IP, c.id, "Вася")
    assert same.label == "Вася"


def test_rename_missing(mgr: ClientManager) -> None:
    with pytest.raises(ClientNotFound):
        mgr.rename_client(IP, "no-such", "X")


# ---------- disable / enable ----------


def test_disable(mgr: ClientManager, store: SecretsStore) -> None:
    c = mgr.add_client(IP, "Вася")
    mgr.disable_client(IP, c.id)
    loaded = store.load(IP)
    assert loaded.clients[0].disabled is True


def test_enable(mgr: ClientManager, store: SecretsStore) -> None:
    c = mgr.add_client(IP, "Вася")
    mgr.disable_client(IP, c.id)
    mgr.enable_client(IP, c.id)
    loaded = store.load(IP)
    assert loaded.clients[0].disabled is False


def test_disable_missing(mgr: ClientManager) -> None:
    with pytest.raises(ClientNotFound):
        mgr.disable_client(IP, "no-such")


def test_disable_does_not_change_identity(mgr: ClientManager) -> None:
    c = mgr.add_client(IP, "Вася")
    mgr.disable_client(IP, c.id)
    loaded = mgr.get_client(IP, c.id)
    assert loaded.sub_token == c.sub_token
    assert loaded.vless_uuid == c.vless_uuid
    assert loaded.hysteria_user == c.hysteria_user
    assert loaded.hysteria_pass == c.hysteria_pass


# ---------- rotate_all ----------


def test_rotate_all_snapshots_before(mgr: ClientManager, store: SecretsStore) -> None:
    mgr.add_client(IP, "Вася")
    mgr.rotate_all(IP)
    archive = store.root / "_archive"
    files = list(archive.glob(f"{IP}.*.rotate.json"))
    assert len(files) == 1


def test_rotate_all_regenerates_client_secrets(
    mgr: ClientManager, store: SecretsStore
) -> None:
    c = mgr.add_client(IP, "Вася")
    old_sub = c.sub_token
    old_uuid = c.vless_uuid
    old_pass = c.hysteria_pass

    rotated = mgr.rotate_all(IP)
    assert len(rotated) == 1
    r = rotated[0]
    assert r.id == c.id
    assert r.label == c.label
    assert r.sub_token != old_sub
    assert r.vless_uuid != old_uuid
    assert r.hysteria_pass != old_pass


def test_rotate_all_preserves_server_secrets(
    mgr: ClientManager, store: SecretsStore
) -> None:
    s = store.load(IP)
    s.domain = "node1.example.com"
    store.save(s)

    mgr.add_client(IP, "Вася")
    mgr.rotate_all(IP)

    loaded = store.load(IP)
    assert loaded.domain == "node1.example.com"


def test_rotate_all_preserves_disabled_flag(mgr: ClientManager) -> None:
    c = mgr.add_client(IP, "Вася")
    mgr.disable_client(IP, c.id)
    rotated = mgr.rotate_all(IP)
    assert rotated[0].disabled is True


def test_rotate_all_no_clients_ok(mgr: ClientManager) -> None:
    rotated = mgr.rotate_all(IP)
    assert rotated == []


def test_rotate_all_snapshot_is_valid_json(
    mgr: ClientManager, store: SecretsStore
) -> None:
    mgr.add_client(IP, "Вася")
    mgr.rotate_all(IP)
    archive = store.root / "_archive"
    snap = next(archive.glob(f"{IP}.*.rotate.json"))
    data = json.loads(snap.read_text(encoding="utf-8"))
    assert data["ip"] == IP
    assert len(data["clients"]) == 1


# ---------- hysteria_user derivation ----------


def test_user_from_label_ascii() -> None:
    assert _user_from_label("Vasya") == "vasya"


def test_user_from_label_cyrillic() -> None:
    assert _user_from_label("Вася") == "vasya"


def test_user_from_label_spaces_and_punct() -> None:
    assert _user_from_label("  Vasya  Pupkin!! ") == "vasya-pupkin"


def test_user_from_label_all_punct_falls_back() -> None:
    u = _user_from_label("!!!")
    assert u.startswith("u")
    assert len(u) <= 32


def test_user_from_label_truncated() -> None:
    long = "a" * 100
    assert len(_user_from_label(long)) == 32


def test_translit_ru_basic() -> None:
    assert _translit_ru("Привет") == "Privet"
