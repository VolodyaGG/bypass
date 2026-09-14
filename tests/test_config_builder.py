"""Tests for vpnforge.config_builder."""

from __future__ import annotations

import json

import pytest

from vpnforge.config_builder import (
    ConfigError,
    _xray_email,
    build_hysteria_config,
    build_xray_config,
)
from vpnforge.models import (
    Client,
    Hysteria2Config,
    ProtocolFlags,
    RealityConfig,
    Secrets,
)


# ---------- fixtures / builders ----------


def _reality() -> RealityConfig:
    return RealityConfig(
        private_key="PRIV_KEY_B64",
        public_key="PUB_KEY_B64",
        short_id="deadbeef",
        dest="www.microsoft.com:443",
        server_name="www.microsoft.com",
        fingerprint="chrome",
        spider_x="/",
        xhttp_path="/",
        xhttp_mode="packet-up",
    )


def _hysteria() -> Hysteria2Config:
    return Hysteria2Config(
        obfs_password="obfs-pass-xyz",
        masquerade_url="https://apple.com",
    )


def _client(
    label: str,
    uuid: str,
    user: str,
    pw: str,
    *,
    disabled: bool = False,
    client_id: str | None = None,
) -> Client:
    return Client(
        id=client_id or f"id-{label}",
        label=label,
        sub_token="a" * 32,
        vless_uuid=uuid,
        hysteria_user=user,
        hysteria_pass=pw,
        disabled=disabled,
    )


def _secrets(
    clients: list[Client],
    *,
    with_reality: bool = True,
    with_hysteria: bool = True,
) -> Secrets:
    return Secrets(
        ip="1.2.3.4",
        domain="node1.example.com",
        protocols=ProtocolFlags(
            vless_reality=with_reality,
            hysteria2=with_hysteria,
            openflux=False,
        ),
        reality=_reality() if with_reality else None,
        hysteria2=_hysteria() if with_hysteria else None,
        clients=clients,
    )


UUID_A = "11111111-1111-4111-8111-111111111111"
UUID_B = "22222222-2222-4222-8222-222222222222"


# ---------- _xray_email ----------


def test_xray_email_basic_ascii() -> None:
    assert _xray_email("vasya", "abcdef1234567890") == "vasya@abcdef12"


def test_xray_email_case_insensitive() -> None:
    assert _xray_email("VaSya", "abcdef1234567890") == "vasya@abcdef12"


def test_xray_email_replaces_spaces_and_punct() -> None:
    email = _xray_email("Vasya Pupkin!!", "abcdef1234567890")
    assert email == "vasya-pupkin@abcdef12"
    assert email.isascii()


def test_xray_email_cyrillic_falls_back_to_client() -> None:
    # all cyrillic chars become '-', then stripped -> empty -> "client"
    assert _xray_email("Вася", "abcdef1234567890") == "client@abcdef12"


def test_xray_email_mixed_keeps_ascii_part() -> None:
    # 'Vasya' survives, cyrillic part becomes '-', trailing stripped
    email = _xray_email("Vasya Вася", "abcdef1234567890")
    assert email == "vasya@abcdef12"


def test_xray_email_truncates_long_local() -> None:
    email = _xray_email("a" * 100, "abcdef1234567890")
    local = email.split("@")[0]
    assert len(local) <= 24
    assert local == "a" * 24


def test_xray_email_domain_is_id_prefix() -> None:
    email = _xray_email("vasya", "deadbeefcafebabe")
    _, _, domain = email.partition("@")
    assert domain == "deadbeef"


def test_xray_email_collapses_repeated_dashes_from_strip() -> None:
    # "Vasya  Pupkin" -> "vasya--pupkin" via simple char mapping, but
    # our impl does NOT collapse; document actual behaviour here.
    email = _xray_email("Vasya  Pupkin", "abcdef1234567890")
    assert email == "vasya--pupkin@abcdef12"


# ---------- build_xray_config: errors ----------


def test_xray_raises_without_reality() -> None:
    s = _secrets([], with_reality=False)
    with pytest.raises(ConfigError):
        build_xray_config(s)


# ---------- build_xray_config: shape ----------


def test_xray_top_level_keys() -> None:
    c = _client("vasya", UUID_A, "vasya", "pw")
    cfg = build_xray_config(_secrets([c]))
    assert set(cfg.keys()) == {"log", "inbounds", "outbounds", "routing"}


def test_xray_log_level_warning() -> None:
    c = _client("vasya", UUID_A, "vasya", "pw")
    cfg = build_xray_config(_secrets([c]))
    assert cfg["log"] == {"loglevel": "warning"}


def test_xray_single_inbound() -> None:
    c = _client("vasya", UUID_A, "vasya", "pw")
    cfg = build_xray_config(_secrets([c]))
    assert len(cfg["inbounds"]) == 1


def test_xray_inbound_keys() -> None:
    c = _client("vasya", UUID_A, "vasya", "pw")
    cfg = build_xray_config(_secrets([c]))
    inbound = cfg["inbounds"][0]
    assert set(inbound.keys()) == {
        "tag",
        "listen",
        "port",
        "protocol",
        "settings",
        "streamSettings",
        "sniffing",
    }


def test_xray_inbound_basic_fields() -> None:
    c = _client("vasya", UUID_A, "vasya", "pw")
    inbound = build_xray_config(_secrets([c]))["inbounds"][0]
    assert inbound["tag"] == "vless-reality-xhttp"
    assert inbound["listen"] == "0.0.0.0"
    assert inbound["port"] == 443
    assert inbound["protocol"] == "vless"


def test_xray_inbound_settings() -> None:
    c = _client("vasya", UUID_A, "vasya", "pw")
    inbound = build_xray_config(_secrets([c]))["inbounds"][0]
    assert inbound["settings"]["decryption"] == "none"
    assert "clients" in inbound["settings"]


def test_xray_stream_settings_network_and_security() -> None:
    c = _client("vasya", UUID_A, "vasya", "pw")
    ss = build_xray_config(_secrets([c]))["inbounds"][0]["streamSettings"]
    assert ss["network"] == "xhttp"
    assert ss["security"] == "reality"


def test_xray_reality_settings_full() -> None:
    c = _client("vasya", UUID_A, "vasya", "pw")
    ss = build_xray_config(_secrets([c]))["inbounds"][0]["streamSettings"]
    rs = ss["realitySettings"]
    assert rs["show"] is False
    assert rs["dest"] == "www.microsoft.com:443"
    assert rs["xver"] == 0
    assert rs["serverNames"] == ["www.microsoft.com"]
    assert rs["privateKey"] == "PRIV_KEY_B64"
    assert rs["shortIds"] == ["deadbeef"]


def test_xray_xhttp_settings() -> None:
    c = _client("vasya", UUID_A, "vasya", "pw")
    ss = build_xray_config(_secrets([c]))["inbounds"][0]["streamSettings"]
    assert ss["xhttpSettings"] == {"path": "/", "mode": "packet-up"}


def test_xray_sniffing_enabled() -> None:
    c = _client("vasya", UUID_A, "vasya", "pw")
    inbound = build_xray_config(_secrets([c]))["inbounds"][0]
    assert inbound["sniffing"]["enabled"] is True
    assert set(inbound["sniffing"]["destOverride"]) == {"http", "tls", "quic"}


def test_xray_outbounds_freedom_and_blackhole() -> None:
    c = _client("vasya", UUID_A, "vasya", "pw")
    cfg = build_xray_config(_secrets([c]))
    protos = {o["protocol"] for o in cfg["outbounds"]}
    assert protos == {"freedom", "blackhole"}


def test_xray_routing_blocks_private_geoip() -> None:
    c = _client("vasya", UUID_A, "vasya", "pw")
    cfg = build_xray_config(_secrets([c]))
    rules = cfg["routing"]["rules"]
    assert any(
        r.get("ip") == ["geoip:private"] and r.get("outboundTag") == "block"
        for r in rules
    )


def test_xray_no_api_inbound() -> None:
    c = _client("vasya", UUID_A, "vasya", "pw")
    cfg = build_xray_config(_secrets([c]))
    assert "api" not in cfg
    assert "stats" not in cfg
    assert "policy" not in cfg


# ---------- build_xray_config: clients ----------


def test_xray_client_entry_shape() -> None:
    c = _client("vasya", UUID_A, "vasya", "pw", client_id="abcdef1234567890")
    clients = build_xray_config(_secrets([c]))["inbounds"][0]["settings"]["clients"]
    assert clients == [{"id": UUID_A, "email": "vasya@abcdef12"}]


def test_xray_two_clients_both_present() -> None:
    a = _client("vasya", UUID_A, "vasya", "pw1")
    b = _client("petya", UUID_B, "petya", "pw2")
    clients = build_xray_config(_secrets([a, b]))["inbounds"][0]["settings"]["clients"]
    uuids = {x["id"] for x in clients}
    assert uuids == {UUID_A, UUID_B}


def test_xray_disabled_excluded() -> None:
    a = _client("vasya", UUID_A, "vasya", "pw1")
    b = _client("petya", UUID_B, "petya", "pw2", disabled=True)
    clients = build_xray_config(_secrets([a, b]))["inbounds"][0]["settings"]["clients"]
    assert [x["id"] for x in clients] == [UUID_A]


def test_xray_all_disabled_yields_empty_clients() -> None:
    a = _client("vasya", UUID_A, "vasya", "pw1", disabled=True)
    clients = build_xray_config(_secrets([a]))["inbounds"][0]["settings"]["clients"]
    assert clients == []


def test_xray_no_clients_ok() -> None:
    cfg = build_xray_config(_secrets([]))
    assert cfg["inbounds"][0]["settings"]["clients"] == []


def test_xray_emails_unique_with_same_label() -> None:
    a = _client("vasya", UUID_A, "vasya", "pw1", client_id="aaaaaaaa11111111")
    b = _client("vasya", UUID_B, "vasya2", "pw2", client_id="bbbbbbbb22222222")
    clients = build_xray_config(_secrets([a, b]))["inbounds"][0]["settings"]["clients"]
    emails = [x["email"] for x in clients]
    assert len(set(emails)) == 2


def test_xray_private_key_appears_once() -> None:
    """Sanity: PRIV_KEY_B64 only in realitySettings, not leaked elsewhere."""
    c = _client("vasya", UUID_A, "vasya", "pw")
    cfg = build_xray_config(_secrets([c]))
    assert json.dumps(cfg).count("PRIV_KEY_B64") == 1


def test_xray_all_client_emails_ascii() -> None:
    a = _client("Вася", UUID_A, "vasya", "pw1")
    b = _client("Петя", UUID_B, "petya", "pw2")
    clients = build_xray_config(_secrets([a, b]))["inbounds"][0]["settings"]["clients"]
    for entry in clients:
        assert entry["email"].isascii()


def test_xray_json_serializable() -> None:
    a = _client("Вася", UUID_A, "vasya", "pw1")
    json.dumps(build_xray_config(_secrets([a])))  # must not raise


# ---------- build_hysteria_config: errors ----------


def test_hysteria_raises_without_config() -> None:
    s = _secrets([], with_hysteria=False)
    with pytest.raises(ConfigError):
        build_hysteria_config(s)


def test_hysteria_duplicate_user_raises() -> None:
    a = _client("a", UUID_A, "same", "pw1")
    b = _client("b", UUID_B, "same", "pw2")
    with pytest.raises(ConfigError, match="duplicate hysteria_user"):
        build_hysteria_config(_secrets([a, b]))


def test_hysteria_duplicate_ignores_disabled() -> None:
    a = _client("a", UUID_A, "same", "pw1")
    b = _client("b", UUID_B, "same", "pw2", disabled=True)
    cfg = build_hysteria_config(_secrets([a, b]))
    assert cfg["auth"]["userpass"] == {"same": "pw1"}


# ---------- build_hysteria_config: shape ----------


def test_hysteria_top_level_keys() -> None:
    c = _client("vasya", UUID_A, "vasya", "pw")
    cfg = build_hysteria_config(_secrets([c]))
    assert set(cfg.keys()) == {
        "listen",
        "tls",
        "auth",
        "masquerade",
        "obfs",
        "bandwidth",
        "ignoreClientBandwidth",
        "disableUDP",
    }


def test_hysteria_listen() -> None:
    c = _client("vasya", UUID_A, "vasya", "pw")
    cfg = build_hysteria_config(_secrets([c]))
    assert cfg["listen"] == ":443"


def test_hysteria_tls_paths() -> None:
    c = _client("vasya", UUID_A, "vasya", "pw")
    cfg = build_hysteria_config(_secrets([c]))
    assert cfg["tls"]["cert"] == "/etc/vpnforge/certs/fullchain.pem"
    assert cfg["tls"]["key"] == "/etc/vpnforge/certs/privkey.pem"


def test_hysteria_auth_userpass_type() -> None:
    c = _client("vasya", UUID_A, "vasya", "pw")
    cfg = build_hysteria_config(_secrets([c]))
    assert cfg["auth"]["type"] == "userpass"
    assert cfg["auth"]["userpass"] == {"vasya": "pw"}


def test_hysteria_masquerade_proxy_url() -> None:
    c = _client("vasya", UUID_A, "vasya", "pw")
    cfg = build_hysteria_config(_secrets([c]))
    assert cfg["masquerade"]["type"] == "proxy"
    assert cfg["masquerade"]["proxy"]["url"] == "https://apple.com"
    assert cfg["masquerade"]["proxy"]["rewriteHost"] is True


def test_hysteria_obfs_salamander() -> None:
    c = _client("vasya", UUID_A, "vasya", "pw")
    cfg = build_hysteria_config(_secrets([c]))
    assert cfg["obfs"]["type"] == "salamander"
    assert cfg["obfs"]["salamander"]["password"] == "obfs-pass-xyz"


def test_hysteria_bandwidth_placeholder() -> None:
    c = _client("vasya", UUID_A, "vasya", "pw")
    cfg = build_hysteria_config(_secrets([c]))
    assert cfg["bandwidth"] == {"up": "1 gbps", "down": "1 gbps"}


def test_hysteria_flags() -> None:
    c = _client("vasya", UUID_A, "vasya", "pw")
    cfg = build_hysteria_config(_secrets([c]))
    assert cfg["ignoreClientBandwidth"] is False
    assert cfg["disableUDP"] is False


# ---------- build_hysteria_config: clients ----------


def test_hysteria_two_clients() -> None:
    a = _client("vasya", UUID_A, "vasya", "pw1")
    b = _client("petya", UUID_B, "petya", "pw2")
    cfg = build_hysteria_config(_secrets([a, b]))
    assert cfg["auth"]["userpass"] == {"vasya": "pw1", "petya": "pw2"}


def test_hysteria_disabled_excluded() -> None:
    a = _client("vasya", UUID_A, "vasya", "pw1")
    b = _client("petya", UUID_B, "petya", "pw2", disabled=True)
    cfg = build_hysteria_config(_secrets([a, b]))
    assert cfg["auth"]["userpass"] == {"vasya": "pw1"}


def test_hysteria_all_disabled_empty_userpass() -> None:
    a = _client("vasya", UUID_A, "vasya", "pw1", disabled=True)
    cfg = build_hysteria_config(_secrets([a]))
    assert cfg["auth"]["userpass"] == {}


def test_hysteria_no_clients_ok() -> None:
    cfg = build_hysteria_config(_secrets([]))
    assert cfg["auth"]["userpass"] == {}


def test_hysteria_json_serializable() -> None:
    a = _client("Вася", UUID_A, "vasya", "pw1")
    json.dumps(build_hysteria_config(_secrets([a])))  # must not raise