"""Build client-facing artifacts: shareable URLs, base64 subscription, clients.json.

Invariants:
  * disabled clients are excluded everywhere;
  * server-side secrets (reality.private_key) never appear in output;
  * VLESS URL uses IP when domain is absent; Hysteria 2 REQUIRES a domain
    (its TLS SNI must match a real certificate), so we raise in that case.
"""

from __future__ import annotations

import base64
import json
from typing import Any
from urllib.parse import quote, urlencode

from vpnforge.models import Client, Secrets


class SubBuildError(Exception):
    """Raised when subscription artifacts cannot be built."""


# ---------- URL builders ----------


def build_vless_url(secrets: Secrets, client: Client) -> str:
    """Build a vless:// URL for one client."""
    if secrets.reality is None:
        raise SubBuildError("reality config is missing")

    r = secrets.reality
    host = secrets.domain or secrets.ip
    label = _fragment_label(client.label, secrets.domain or secrets.ip, "reality")

    params = {
        "type": "tcp",
        "security": "reality",
        "flow": "xtls-rprx-vision",
        "pbk": r.public_key,
        "fp": r.fingerprint,
        "sni": r.server_name,
        "sid": r.short_id,
        "spx": r.spider_x,
    }

    query = urlencode(params, quote_via=quote, safe="")
    return (
        f"vless://{client.vless_uuid}@{host}:443?{query}#{quote(label)}"
    )


def build_hysteria_url(secrets: Secrets, client: Client) -> str:
    """Build a hysteria2:// URL for one client."""
    if secrets.hysteria2 is None:
        raise SubBuildError("hysteria2 config is missing")
    if not secrets.domain:
        raise SubBuildError("hysteria2 requires a domain (TLS SNI must match cert)")

    h = secrets.hysteria2
    host = secrets.domain
    label = _fragment_label(client.label, host, "hy2")

    params = {
        "sni": host,
        "insecure": "0",
        "obfs": "salamander",
        "obfs-password": h.obfs_password,
    }
    query = urlencode(params, quote_via=quote, safe="")

    auth = quote(f"{client.hysteria_user}:{client.hysteria_pass}", safe="")

    return f"hysteria2://{auth}@{host}:443/?{query}#{quote(label)}"


def encode_subscription(urls: list[str]) -> str:
    """Base64-encode a newline-joined list of URLs (standard base64, with padding)."""
    raw = "\n".join(urls).encode("utf-8")
    return base64.b64encode(raw).decode("ascii")


def build_subscription_for_client(secrets: Secrets, client: Client) -> list[str]:
    """Return all enabled share URLs for one client (empty if disabled)."""
    if client.disabled:
        return []

    urls: list[str] = []
    if secrets.protocols.vless_reality and secrets.reality is not None:
        urls.append(build_vless_url(secrets, client))
    if secrets.protocols.hysteria2 and secrets.hysteria2 is not None:
        # Raises if no domain — deliberate, see module docstring.
        urls.append(build_hysteria_url(secrets, client))
    return urls


def build_xray_client_config(secrets: Secrets, client: Client) -> dict[str, Any]:
    """Build a complete Xray client profile with Russian traffic sent direct."""
    if client.disabled:
        raise SubBuildError("client is disabled")
    if not secrets.protocols.vless_reality or secrets.reality is None:
        raise SubBuildError("VLESS Reality is required for an Xray profile")

    reality = secrets.reality
    host = secrets.domain or secrets.ip
    direct_rules: list[dict[str, Any]] = []

    if secrets.routing.private_direct:
        direct_rules.extend(
            [
                {
                    "type": "field",
                    "ip": ["geoip:private"],
                    "outboundTag": "direct",
                },
                {
                    "type": "field",
                    "domain": ["geosite:private"],
                    "outboundTag": "direct",
                },
            ]
        )

    if secrets.routing.ru_direct:
        direct_rules.extend(
            [
                {
                    "type": "field",
                    "domain": ["geosite:category-ru"],
                    "outboundTag": "direct",
                },
                {
                    "type": "field",
                    "ip": ["geoip:ru"],
                    "outboundTag": "direct",
                },
            ]
        )

    if secrets.routing.custom_direct_domains:
        direct_rules.append(
            {
                "type": "field",
                "domain": [
                    f"domain:{domain}"
                    for domain in secrets.routing.custom_direct_domains
                ],
                "outboundTag": "direct",
            }
        )

    return {
        "log": {"loglevel": "warning"},
        "inbounds": [
            {
                "tag": "socks-in",
                "listen": "127.0.0.1",
                "port": 10808,
                "protocol": "socks",
                "settings": {"udp": True},
                "sniffing": {
                    "enabled": True,
                    "destOverride": ["http", "tls", "quic"],
                    "routeOnly": True,
                },
            }
        ],
        "outbounds": [
            {
                "tag": "proxy",
                "protocol": "vless",
                "settings": {
                    "vnext": [
                        {
                            "address": host,
                            "port": 443,
                            "users": [
                                {
                                    "id": client.vless_uuid,
                                    "encryption": "none",
                                    "flow": "xtls-rprx-vision",
                                }
                            ],
                        }
                    ]
                },
                "streamSettings": {
                    "network": "tcp",
                    "tcpSettings": {"header": {"type": "none"}},
                    "security": "reality",
                    "realitySettings": {
                        "serverName": reality.server_name,
                        "fingerprint": reality.fingerprint,
                        "password": reality.public_key,
                        "shortId": reality.short_id,
                        "spiderX": reality.spider_x,
                    },
                },
            },
            {"tag": "direct", "protocol": "freedom"},
            {"tag": "block", "protocol": "blackhole"},
        ],
        "routing": {
            "domainStrategy": "IPIfNonMatch",
            "rules": [
                *direct_rules,
                {
                    "type": "field",
                    "network": "tcp,udp",
                    "outboundTag": "proxy",
                },
            ],
        },
    }


def dump_xray_client_config(secrets: Secrets, client: Client) -> str:
    return json.dumps(
        build_xray_client_config(secrets, client),
        indent=2,
        ensure_ascii=False,
    )


# ---------- clients.json ----------


def build_clients_json(secrets: Secrets) -> dict[str, Any]:
    """Assemble the clients.json document consumed by vps_sub_server.

    Contains pre-rendered URLs per client. Server-side private keys are
    NOT included.
    """
    enabled = [c for c in secrets.clients if not c.disabled]

    clients_out: list[dict[str, Any]] = []
    for c in enabled:
        urls = build_subscription_for_client(secrets, c)
        clients_out.append(
            {
                "id": c.id,
                "label": c.label,
                "sub_token": c.sub_token,
                "urls": urls,
                "xray_config": build_xray_client_config(secrets, c)
                if secrets.protocols.vless_reality
                else None,
            }
        )

    doc: dict[str, Any] = {
        "version": 1,
        "server": {
            "ip": secrets.ip,
            "domain": secrets.domain,
        },
        "protocols": {
            "vless_reality": secrets.protocols.vless_reality,
            "hysteria2": secrets.protocols.hysteria2,
        },
        "routing": secrets.routing.model_dump(mode="json"),
        "clients": clients_out,
    }
    return doc


def dump_clients_json(secrets: Secrets) -> str:
    """Serialize clients.json deterministically (stable for golden tests)."""
    return json.dumps(build_clients_json(secrets), indent=2, ensure_ascii=False)


# ---------- internals ----------


def _fragment_label(label: str, host: str, suffix: str) -> str:
    """Fragment for the `#...` part of the URL.

    Kept human-readable: "<label> (<host> <suffix>)".
    """
    safe_label = label.strip() or "client"
    return f"{safe_label} ({host} {suffix})"
