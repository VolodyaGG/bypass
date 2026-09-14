"""Build server-side configs (Xray, Hysteria 2) from a Secrets document.

Pure functions: no filesystem, no network. Caller (main.py) is responsible
for loading Secrets and for writing the resulting dicts to disk / feeding
them to Jinja templates.

Invariants:
  * disabled clients are excluded from `clients[]` everywhere;
  * each enabled client carries its own UUID / userpass;
  * Reality keys come from `secrets.reality`, never regenerated here.
"""

from __future__ import annotations

from typing import Any

from vpnforge.models import Secrets


class ConfigError(Exception):
    """Raised when the Secrets document lacks what the builder needs."""


# ---------- Xray ----------


def build_xray_config(secrets: Secrets) -> dict[str, Any]:
    """Return a full Xray server config dict (no api inbound)."""
    if secrets.reality is None:
        raise ConfigError("reality config is missing in secrets")

    r = secrets.reality
    enabled_clients = [c for c in secrets.clients if not c.disabled]

    clients: list[dict[str, Any]] = [
        {
            "id": c.vless_uuid,
            "email": _xray_email(c.label, c.id),
        }
        for c in enabled_clients
    ]

    config: dict[str, Any] = {
        "log": {"loglevel": "warning"},
        "inbounds": [
            {
                "tag": "vless-reality-xhttp",
                "listen": "0.0.0.0",
                "port": 443,
                "protocol": "vless",
                "settings": {
                    "clients": clients,
                    "decryption": "none",
                },
                "streamSettings": {
                    "network": "xhttp",
                    "security": "reality",
                    "realitySettings": {
                        "show": False,
                        "dest": r.dest,
                        "xver": 0,
                        "serverNames": [r.server_name],
                        "privateKey": r.private_key,
                        "shortIds": [r.short_id],
                    },
                    "xhttpSettings": {
                        "path": r.xhttp_path,
                        "mode": r.xhttp_mode,
                    },
                },
                "sniffing": {
                    "enabled": True,
                    "destOverride": ["http", "tls", "quic"],
                },
            }
        ],
        "outbounds": [
            {"protocol": "freedom", "tag": "direct"},
            {"protocol": "blackhole", "tag": "block"},
        ],
        "routing": {
            "rules": [
                {
                    "type": "field",
                    "ip": ["geoip:private"],
                    "outboundTag": "block",
                }
            ]
        },
    }

    return config


def _xray_email(label: str, client_id: str) -> str:
    """Xray `email` field is a free-form identifier.

    We keep it ASCII-safe (Xray logs it verbatim) and guarantee uniqueness
    by appending the client id prefix. Format: <short-label>@<id8>.
    """
    local = "".join(
        ch if (ch.isalnum() and ch.isascii()) else "-" for ch in label.lower()
    ).strip("-") or "client"
    local = local[:24]
    return f"{local}@{client_id[:8]}"


# ---------- Hysteria 2 ----------


def build_hysteria_config(secrets: Secrets) -> dict[str, Any]:
    """Return a Hysteria 2 server config dict."""
    if secrets.hysteria2 is None:
        raise ConfigError("hysteria2 config is missing in secrets")

    enabled_clients = [c for c in secrets.clients if not c.disabled]

    # Hysteria 2 userpass: {"user": "password"}
    userpass: dict[str, str] = {c.hysteria_user: c.hysteria_pass for c in enabled_clients}

    # Detect duplicate usernames (should not happen — manager enforces it —
    # but be defensive: a duplicate would silently drop a user otherwise).
    if len(userpass) != len(enabled_clients):
        seen: dict[str, int] = {}
        for c in enabled_clients:
            seen[c.hysteria_user] = seen.get(c.hysteria_user, 0) + 1
        dupes = [u for u, n in seen.items() if n > 1]
        raise ConfigError(f"duplicate hysteria_user in clients: {dupes}")

    config: dict[str, Any] = {
        "listen": ":443",
        "tls": {
            "cert": "/etc/vpnforge/certs/fullchain.pem",
            "key": "/etc/vpnforge/certs/privkey.pem",
        },
        "auth": {
            "type": "userpass",
            "userpass": userpass,
        },
        "masquerade": {
            "type": "proxy",
            "proxy": {
                "url": secrets.hysteria2.masquerade_url,
                "rewriteHost": True,
            },
        },
        "obfs": {
            "type": "salamander",
            "salamander": {
                "password": secrets.hysteria2.obfs_password,
            },
        },
        "bandwidth": {
            "up": "1 gbps",
            "down": "1 gbps",
        },
        "ignoreClientBandwidth": False,
        "disableUDP": False,
    }

    return config