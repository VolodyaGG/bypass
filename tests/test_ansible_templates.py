"""Regression tests for security-sensitive systemd templates."""

import json
from pathlib import Path

from jinja2 import Environment, FileSystemLoader


def test_subscription_unit_keeps_execstart_and_restart_on_separate_lines() -> None:
    root = Path(__file__).resolve().parents[1]
    environment = Environment(
        loader=FileSystemLoader(root / "ansible"),
        trim_blocks=True,
        lstrip_blocks=True,
        autoescape=False,
    )
    template = environment.get_template("templates/vpnforge-sub.service.j2")
    rendered = template.render(
        vpnforge={
            "clients_json_path": "/opt/vpnforge/sub/clients.json",
            "subscription_port": 8444,
            "subscription_scheme": "https",
        }
    )

    assert "privkey.pem\nRestart=always" in rendered
    assert "privkey.pemRestart=always" not in rendered


def test_xray_verification_client_uses_real_credentials_and_tcp() -> None:
    root = Path(__file__).resolve().parents[1]
    environment = Environment(
        loader=FileSystemLoader(root / "ansible"),
        trim_blocks=True,
        lstrip_blocks=True,
        autoescape=False,
    )
    environment.filters["to_json"] = json.dumps
    template = environment.get_template("templates/verify-xray-client.json.j2")
    rendered = template.render(
        xray_config={
            "inbounds": [{
                "settings": {"clients": [{"id": "client-uuid", "flow": "xtls-rprx-vision"}]}
            }]
        },
        reality={
            "server_name": "www.apple.com",
            "fingerprint": "chrome",
            "public_key": "reality-public-key",
            "short_id": "deadbeef",
        },
    )
    config = json.loads(rendered)

    outbound = config["outbounds"][0]
    assert outbound["settings"]["vnext"][0]["users"][0]["id"] == "client-uuid"
    assert outbound["settings"]["vnext"][0]["users"][0]["flow"] == "xtls-rprx-vision"
    assert outbound["streamSettings"]["network"] == "tcp"
    assert outbound["streamSettings"]["tcpSettings"] == {"header": {"type": "none"}}
    assert (
        outbound["streamSettings"]["realitySettings"]["password"]
        == "reality-public-key"
    )


def test_hysteria_verification_client_uses_published_url() -> None:
    root = Path(__file__).resolve().parents[1]
    environment = Environment(
        loader=FileSystemLoader(root / "ansible"),
        trim_blocks=True,
        lstrip_blocks=True,
        autoescape=False,
    )
    environment.filters["to_json"] = json.dumps
    template = environment.get_template("templates/verify-hysteria-client.json.j2")
    url = "hysteria2://user%3Apass@node.example.com:443/?sni=node.example.com"
    rendered = template.render(
        clients_json={"clients": [{"urls": ["vless://example", url]}]}
    )
    config = json.loads(rendered)

    assert config["server"] == url
    assert config["socks5"]["listen"] == "127.0.0.1:11809"
