"""Tests for vpnforge.inventory_builder."""

from __future__ import annotations

import base64
from datetime import UTC, datetime
from pathlib import Path

import pytest
import yaml

from vpnforge.inventory_builder import (
    InventoryError,
    build_group_vars,
    build_hosts_ini,
    dump_group_vars,
    encode_pem_b64,
)
from vpnforge.models import (
    CertInfo,
    Client,
    Hysteria2Config,
    OpenFluxConfig,
    ProtocolFlags,
    RealityConfig,
    Secrets,
    VPSConnection,
)
from vpnforge.openflux_manager import OpenFluxError

# ---------- fixtures ----------


def _vps(**overrides) -> VPSConnection:
    base = {
        "ip": "1.2.3.4",
        "ssh_user": "root",
        "ssh_port": 22,
        "ssh_private_key_path": "/home/user/.ssh/vps_key",
        "ssh_password": None,
    }
    base.update(overrides)
    return VPSConnection(**base)


def _reality() -> RealityConfig:
    return RealityConfig(
        private_key="PRIVATE",
        public_key="PUBLIC",
        short_id="deadbeef",
        dest="www.microsoft.com:443",
        server_name="www.microsoft.com",
    )


def _hysteria() -> Hysteria2Config:
    return Hysteria2Config(obfs_password="obfs-pw", masquerade_url="https://apple.com")


def _cert() -> CertInfo:
    return CertInfo(
        subject_cn="node1.example.com",
        san_domains=["node1.example.com"],
        not_before=datetime(2026, 9, 1, tzinfo=UTC),
        not_after=datetime(2026, 12, 1, tzinfo=UTC),
        issuer_cn="R3",
        sha256="deadbeef" * 8,
    )


def _client(label: str = "Вася") -> Client:
    return Client(
        id="cid-1",
        label=label,
        sub_token="a" * 32,
        vless_uuid="11111111-1111-4111-8111-111111111111",
        hysteria_user="vasya",
        hysteria_pass="pw",
    )


def _secrets(
    *,
    with_reality: bool = True,
    with_hysteria: bool = True,
    with_openflux: bool = False,
    domain: str | None = "node1.example.com",
) -> Secrets:
    s = Secrets(
        ip="1.2.3.4",
        domain=domain,
        protocols=ProtocolFlags(
            vless_reality=with_reality,
            hysteria2=with_hysteria,
            openflux=with_openflux,
        ),
        clients=[_client()],
    )
    if with_reality:
        s.reality = _reality()
    if with_hysteria:
        s.hysteria2 = _hysteria()
    if with_openflux:
        s.openflux = OpenFluxConfig(
            transport="cupsonline",
            yandex_url="https://ya.ru",
        )
    return s


# ---------- hosts.ini ----------


def test_hosts_ini_basic() -> None:
    ini = build_hosts_ini(_vps())
    assert "[vpn]" in ini
    assert "1.2.3.4 ansible_host=1.2.3.4" in ini
    assert "ansible_user=root" in ini
    assert "ansible_port=22" in ini
    assert "ansible_ssh_private_key_file=/home/user/.ssh/vps_key" in ini


def test_hosts_ini_no_key_path() -> None:
    ini = build_hosts_ini(_vps(ssh_private_key_path=None))
    assert "ansible_ssh_private_key_file" not in ini


def test_hosts_ini_never_contains_password() -> None:
    ini = build_hosts_ini(_vps(ssh_password="super-secret"))
    assert "super-secret" not in ini
    assert "ansible_password" not in ini


def test_hosts_ini_has_strict_host_key_accept_new() -> None:
    ini = build_hosts_ini(_vps())
    assert "StrictHostKeyChecking=accept-new" in ini


def test_hosts_ini_custom_port() -> None:
    ini = build_hosts_ini(_vps(ssh_port=2222))
    assert "ansible_port=2222" in ini


def test_hosts_ini_parses_as_ini() -> None:
    """Sanity: section header on first line, trailing newline at end."""
    ini = build_hosts_ini(_vps())
    assert ini.startswith("[vpn]\n")
    assert ini.endswith("\n")


def test_hosts_ini_rejects_empty_ip() -> None:
    with pytest.raises(InventoryError):
        build_hosts_ini(_vps(ip=""))


# ---------- build_group_vars: validation ----------


def test_gv_rejects_unknown_runtime() -> None:
    with pytest.raises(InventoryError, match="unknown runtime"):
        build_group_vars(
            _secrets(with_hysteria=False),
            cert=None,
            runtime="kubernetes",
        )


def test_gv_hysteria_requires_b64() -> None:
    with pytest.raises(InventoryError, match="fullchain_b64"):
        build_group_vars(_secrets(), cert=_cert())


def test_gv_hysteria_requires_domain() -> None:
    with pytest.raises(InventoryError, match="requires secrets.domain"):
        build_group_vars(
            _secrets(domain=None, with_reality=False, with_hysteria=True),
            cert=_cert(),
            fullchain_b64="Zm9v",
            privkey_b64="YmFy",
        )


def test_gv_hysteria_requires_cert() -> None:
    with pytest.raises(InventoryError, match="requires parsed CertInfo"):
        build_group_vars(
            _secrets(),
            cert=None,
            fullchain_b64="Zm9v",
            privkey_b64="YmFy",
        )


def test_gv_hysteria_accepts_existing_vps_certificate() -> None:
    gv = build_group_vars(
        _secrets(),
        cert=None,
        certificate_source="vps",
        vps_fullchain_path="/etc/letsencrypt/live/node1.example.com/fullchain.pem",
        vps_privkey_path="/etc/letsencrypt/live/node1.example.com/privkey.pem",
    )
    hysteria = gv["hysteria2"]
    assert hysteria["certificate_source"] == "vps"
    assert hysteria["fullchain_b64"] is None
    assert hysteria["vps_fullchain_path"].endswith("/fullchain.pem")


def test_gv_hysteria_vps_certificate_requires_both_paths() -> None:
    with pytest.raises(InventoryError, match="certificate paths on VPS"):
        build_group_vars(
            _secrets(),
            cert=None,
            certificate_source="vps",
            vps_fullchain_path="/etc/letsencrypt/live/node1.example.com/fullchain.pem",
        )


def test_gv_reality_requires_config() -> None:
    s = _secrets(with_reality=True, with_hysteria=False)
    s.reality = None
    with pytest.raises(InventoryError, match="reality config missing"):
        build_group_vars(s, cert=None)


def test_gv_hysteria_config_missing() -> None:
    s = _secrets(with_reality=False, with_hysteria=True)
    s.hysteria2 = None
    with pytest.raises(InventoryError, match="hysteria2 config missing"):
        build_group_vars(s, cert=_cert(), fullchain_b64="Zm9v", privkey_b64="YmFy")


# ---------- build_group_vars: contents ----------


def test_gv_common_section() -> None:
    gv = build_group_vars(_secrets(with_hysteria=False), cert=None)
    assert gv["vpnforge"]["runtime"] == "native"
    assert gv["vpnforge"]["server_ip"] == "1.2.3.4"
    assert gv["vpnforge"]["server_domain"] == "node1.example.com"
    assert gv["vpnforge"]["clients_json_path"] == "/opt/vpnforge/sub/clients.json"
    assert gv["vpnforge"]["subscription_scheme"] == "http"
    assert gv["vpnforge"]["subscription_port"] == 8080


def test_gv_subscription_without_certificate_uses_http() -> None:
    gv = build_group_vars(_secrets(with_hysteria=False), cert=None)
    assert gv["vpnforge"]["subscription_scheme"] == "http"
    assert gv["vpnforge"]["subscription_port"] == 8080


def test_gv_subscription_with_certificate_uses_https() -> None:
    gv = build_group_vars(
        _secrets(),
        cert=_cert(),
        fullchain_b64="Zm9v",
        privkey_b64="YmFy",
    )
    assert gv["vpnforge"]["subscription_scheme"] == "https"
    assert gv["vpnforge"]["subscription_port"] == 8444


def test_gv_protocols_flags() -> None:
    gv = build_group_vars(
        _secrets(with_reality=True, with_hysteria=True, with_openflux=True),
        cert=_cert(),
        fullchain_b64="Zm9v",
        privkey_b64="YmFy",
    )
    assert gv["protocols"] == {
        "hysteria2": True,
        "vless_reality": True,
        "openflux": True,
    }


def test_gv_reality_block() -> None:
    gv = build_group_vars(_secrets(with_hysteria=False), cert=None)
    r = gv["reality"]
    assert r["private_key"] == "PRIVATE"
    assert r["public_key"] == "PUBLIC"
    assert r["short_id"] == "deadbeef"
    assert r["server_name"] == "www.microsoft.com"
    assert r["fingerprint"] == "chrome"
    assert r["spider_x"] == "/"
    assert r["xhttp_path"] == "/"
    assert r["xhttp_mode"] == "packet-up"


def test_gv_no_reality_block_when_disabled() -> None:
    gv = build_group_vars(
        _secrets(with_reality=False, with_hysteria=True),
        cert=_cert(),
        fullchain_b64="Zm9v",
        privkey_b64="YmFy",
    )
    assert "reality" not in gv


def test_gv_hysteria_block() -> None:
    gv = build_group_vars(
        _secrets(with_reality=False, with_hysteria=True),
        cert=_cert(),
        fullchain_b64="Zm9v",
        privkey_b64="YmFy",
    )
    h = gv["hysteria2"]
    assert h["obfs_password"] == "obfs-pw"
    assert h["masquerade_url"] == "https://apple.com"
    assert h["fullchain_b64"] == "Zm9v"
    assert h["privkey_b64"] == "YmFy"


def test_gv_cert_block_when_hysteria() -> None:
    gv = build_group_vars(
        _secrets(with_reality=False, with_hysteria=True),
        cert=_cert(),
        fullchain_b64="Zm9v",
        privkey_b64="YmFy",
    )
    c = gv["cert"]
    assert c["issuer_cn"] == "R3"
    assert c["not_after"].startswith("2026-12-01")
    assert c["sha256"] == "deadbeef" * 8


def test_gv_no_cert_block_without_hysteria() -> None:
    gv = build_group_vars(_secrets(with_hysteria=False), cert=None)
    assert "cert" not in gv


# ---------- build_group_vars: openflux ----------


def test_gv_openflux_block() -> None:
    gv = build_group_vars(
        _secrets(with_reality=False, with_hysteria=False, with_openflux=True),
        cert=None,
    )
    of = gv["openflux"]
    assert of["transport"] == "cupsonline"
    assert of["mode"] == "l4"
    assert of["codec"] == "batched"
    assert of["yandex_url"] == "https://ya.ru"
    assert of["session_b64"] is None
    assert of["debug"] is False
    assert of["encryption_key"] is None
    assert of["local_ip"] is None
    assert of["max_token"] is None
    assert of["max_uid"] is None


def test_gv_openflux_argv_present() -> None:
    gv = build_group_vars(
        _secrets(with_reality=False, with_hysteria=False, with_openflux=True),
        cert=None,
    )
    argv = gv["openflux"]["argv"]
    assert isinstance(argv, list)
    assert all(isinstance(a, str) for a in argv)
    assert argv[0].endswith("openflux")
    assert "--role" in argv
    assert "exit" in argv
    assert "--transport" in argv
    assert "cupsonline" in argv
    assert "--mode" in argv
    assert "l4" in argv


def test_gv_openflux_argv_has_no_socks5() -> None:
    """--socks5 is a client flag; must never leak into exit-node argv."""
    gv = build_group_vars(
        _secrets(with_reality=False, with_hysteria=False, with_openflux=True),
        cert=None,
    )
    assert "--socks5" not in gv["openflux"]["argv"]


def test_gv_openflux_argv_cupsonline_has_no_url() -> None:
    """cupsonline exit-node must NOT receive --url, even if yandex_url is set."""
    gv = build_group_vars(
        _secrets(with_reality=False, with_hysteria=False, with_openflux=True),
        cert=None,
    )
    # fixture sets yandex_url, but transport is cupsonline -> no --url
    assert "--url" not in gv["openflux"]["argv"]


def test_gv_openflux_yandex_requires_url() -> None:
    """build_exit_node_argv raises OpenFluxError; we propagate, not swallow."""
    s = _secrets(with_reality=False, with_hysteria=False, with_openflux=True)
    s.openflux.transport = "yandex"
    s.openflux.yandex_url = None
    with pytest.raises(OpenFluxError, match="document URL"):
        build_group_vars(s, cert=None)


def test_gv_openflux_oneme_requires_creds() -> None:
    s = _secrets(with_reality=False, with_hysteria=False, with_openflux=True)
    s.openflux.transport = "oneme"
    s.openflux.max_token = None
    s.openflux.max_uid = None
    with pytest.raises(OpenFluxError, match="max_token"):
        build_group_vars(s, cert=None)


def test_gv_openflux_l3_can_auto_detect_local_ip() -> None:
    s = _secrets(with_reality=False, with_hysteria=False, with_openflux=True)
    s.openflux = OpenFluxConfig(transport="cupsonline", mode="raw")
    s.openflux.local_ip = None
    gv = build_group_vars(s, cert=None)
    assert gv["openflux"]["mode"] == "l3"
    assert "--local-ip" not in gv["openflux"]["argv"]


def test_gv_openflux_env_merged() -> None:
    gv = build_group_vars(
        _secrets(with_reality=False, with_hysteria=False, with_openflux=True),
        cert=None,
        openflux_env={"FOO": "bar", "BAZ": "qux"},
    )
    assert gv["openflux"]["env"] == {"FOO": "bar", "BAZ": "qux"}


def test_gv_openflux_env_defaults_to_empty() -> None:
    gv = build_group_vars(
        _secrets(with_reality=False, with_hysteria=False, with_openflux=True),
        cert=None,
    )
    assert gv["openflux"]["env"] == {}


def test_gv_no_openflux_block_when_disabled() -> None:
    gv = build_group_vars(_secrets(with_hysteria=False), cert=None)
    assert "openflux" not in gv


def test_gv_openflux_with_encryption_key_propagates_to_argv() -> None:
    s = _secrets(with_reality=False, with_hysteria=False, with_openflux=True)
    s.openflux.encryption_key = "some-base64-key-material"
    gv = build_group_vars(s, cert=None)
    assert gv["openflux"]["encryption_key"] == "some-base64-key-material"
    assert "--encryption-key-file" in gv["openflux"]["argv"]
    assert "/etc/vpnforge/openflux.key" in gv["openflux"]["argv"]


def test_gv_openflux_debug_propagates_to_argv() -> None:
    s = _secrets(with_reality=False, with_hysteria=False, with_openflux=True)
    s.openflux.debug = True
    gv = build_group_vars(s, cert=None)
    assert gv["openflux"]["debug"] is True
    assert "--debug" in gv["openflux"]["argv"]


# ---------- build_group_vars: ssh password ----------


def test_gv_ssh_password_optional() -> None:
    gv = build_group_vars(
        _secrets(with_hysteria=False),
        cert=None,
        ssh_password="hunter2",
    )
    assert gv["ansible_password"] == "hunter2"


def test_gv_no_ssh_password_by_default() -> None:
    gv = build_group_vars(_secrets(with_hysteria=False), cert=None)
    assert "ansible_password" not in gv


# ---------- build_group_vars: runtime / paths ----------


def test_gv_docker_runtime() -> None:
    gv = build_group_vars(
        _secrets(with_hysteria=False),
        cert=None,
        runtime="docker",
    )
    assert gv["vpnforge"]["runtime"] == "docker"


def test_gv_custom_clients_json_path() -> None:
    gv = build_group_vars(
        _secrets(with_hysteria=False),
        cert=None,
        clients_json_path="/tmp/foo.json",
    )
    assert gv["vpnforge"]["clients_json_path"] == "/tmp/foo.json"


# ---------- dump_group_vars ----------


def test_dump_gv_valid_yaml() -> None:
    gv = build_group_vars(_secrets(with_hysteria=False), cert=None)
    dumped = dump_group_vars(gv)
    parsed = yaml.safe_load(dumped)
    assert parsed["vpnforge"]["server_ip"] == "1.2.3.4"


def test_dump_gv_preserves_cyrillic() -> None:
    gv = build_group_vars(_secrets(with_hysteria=False), cert=None)
    gv["note"] = "Вася"
    dumped = dump_group_vars(gv)
    assert "Вася" in dumped


def test_dump_gv_deterministic() -> None:
    gv = build_group_vars(_secrets(with_hysteria=False), cert=None)
    assert dump_group_vars(gv) == dump_group_vars(gv)


def test_dump_gv_no_python_tags() -> None:
    """safe_dump must not emit !!python/... tags."""
    gv = build_group_vars(_secrets(with_hysteria=False), cert=None)
    dumped = dump_group_vars(gv)
    assert "!!python" not in dumped


def test_dump_gv_openflux_argv_is_yaml_list() -> None:
    """argv list must survive YAML roundtrip."""
    gv = build_group_vars(
        _secrets(with_reality=False, with_hysteria=False, with_openflux=True),
        cert=None,
    )
    parsed = yaml.safe_load(dump_group_vars(gv))
    assert isinstance(parsed["openflux"]["argv"], list)
    assert "--role" in parsed["openflux"]["argv"]


# ---------- encode_pem_b64 ----------


def test_encode_pem_b64_from_bytes() -> None:
    raw = b"-----BEGIN CERTIFICATE-----\nABC\n-----END CERTIFICATE-----\n"
    assert encode_pem_b64(raw) == base64.b64encode(raw).decode("ascii")


def test_encode_pem_b64_from_path(tmp_path: Path) -> None:
    p = tmp_path / "cert.pem"
    p.write_bytes(b"hello")
    assert encode_pem_b64(str(p)) == base64.b64encode(b"hello").decode("ascii")


def test_encode_pem_b64_roundtrip(tmp_path: Path) -> None:
    p = tmp_path / "x.pem"
    original = b"\x00\x01\x02binary"
    p.write_bytes(original)
    assert base64.b64decode(encode_pem_b64(str(p))) == original


# ---------- golden: full yaml for reality-only ----------


def test_golden_gv_reality_only() -> None:
    gv = build_group_vars(_secrets(with_hysteria=False), cert=None)
    expected = {
        "vpnforge": {
            "runtime": "native",
            "server_ip": "1.2.3.4",
            "server_domain": "node1.example.com",
            "clients_json_path": "/opt/vpnforge/sub/clients.json",
            "subscription_scheme": "http",
            "subscription_port": 8080,
        },
        "protocols": {
            "hysteria2": False,
            "vless_reality": True,
            "openflux": False,
        },
        "reality": {
            "private_key": "PRIVATE",
            "public_key": "PUBLIC",
            "short_id": "deadbeef",
            "dest": "www.microsoft.com:443",
            "server_name": "www.microsoft.com",
            "fingerprint": "chrome",
            "spider_x": "/",
            "xhttp_path": "/",
            "xhttp_mode": "packet-up",
        },
    }
    assert gv == expected


def test_golden_gv_openflux_only() -> None:
    """Golden shape for openflux-only deploy (no reality, no hysteria)."""
    gv = build_group_vars(
        _secrets(with_reality=False, with_hysteria=False, with_openflux=True),
        cert=None,
    )
    assert gv["vpnforge"] == {
        "runtime": "native",
        "server_ip": "1.2.3.4",
        "server_domain": "node1.example.com",
        "clients_json_path": "/opt/vpnforge/sub/clients.json",
        "subscription_scheme": "http",
        "subscription_port": 8080,
    }
    assert gv["protocols"] == {
        "hysteria2": False,
        "vless_reality": False,
        "openflux": True,
    }
    assert "reality" not in gv
    assert "hysteria2" not in gv
    assert "cert" not in gv

    of = gv["openflux"]
    # argv is exactly what build_exit_node_argv produces for cupsonline/l4.
    assert of["argv"] == [
        "/usr/local/bin/openflux",
        "--role",
        "exit",
        "--transport",
        "cupsonline",
        "--mode",
        "l4",
        "--codec",
        "batched",
    ]


def test_gv_includes_optional_configs() -> None:
    gv = build_group_vars(
        _secrets(with_hysteria=False),
        cert=None,
        xray_config={"log": {"loglevel": "warning"}},
        hysteria_config={"listen": ":443"},
        clients_json={"version": 1, "clients": []},
    )
    assert gv["xray_config"]["log"]["loglevel"] == "warning"
    assert gv["hysteria_config"]["listen"] == ":443"
    assert gv["clients_json"]["version"] == 1
