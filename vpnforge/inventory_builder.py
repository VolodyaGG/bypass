"""Build Ansible inventory (hosts.ini) and group_vars/all.yml.

Pure functions: no filesystem, no network. Certificates are passed in as
base64-encoded strings (already read by main.py).

Security invariants:
  * SSH password NEVER lands in hosts.ini — only via --extra-vars.
  * group_vars/all.yml is written to a temp run dir and deleted after
    the playbook finishes (see ansible_runner / main).

OpenFlux argv is rendered here (via openflux_manager.build_exit_node_argv)
and passed to Ansible as a pre-joined list, so the Jinja template stays
trivial and we never ship raw secret material in Jinja conditionals.
"""

from __future__ import annotations

import base64
from typing import Any, cast

import yaml

from vpnforge.models import CertInfo, Secrets, VPSConnection
from vpnforge.openflux_manager import build_exit_node_argv


class InventoryError(Exception):
    """Raised when inventory cannot be built."""


# ---------- hosts.ini ----------


def build_hosts_ini(vps: VPSConnection) -> str:
    """Render Ansible INI inventory for a single host.

    Deliberately does NOT include ansible_password: passwords go through
    --extra-vars only.
    """
    if not vps.ip:
        raise InventoryError("vps.ip is required")

    fields = [
        f"ansible_host={vps.ip}",
        f"ansible_user={vps.ssh_user}",
        f"ansible_port={vps.ssh_port}",
        "ansible_ssh_common_args='-o StrictHostKeyChecking=accept-new'",
    ]
    if vps.ssh_private_key_path:
        fields.append(f"ansible_ssh_private_key_file={vps.ssh_private_key_path}")

    lines = [
        "[vpn]",
        f"{vps.ip} " + " ".join(fields),
        "",
    ]
    return "\n".join(lines)


# ---------- group_vars ----------


def build_group_vars(
    secrets: Secrets,
    cert: CertInfo | None,
    *,
    runtime: str = "native",
    certificate_source: str = "upload",
    vps_fullchain_path: str | None = None,
    vps_privkey_path: str | None = None,
    fullchain_b64: str | None = None,
    privkey_b64: str | None = None,
    clients_json_path: str = "/opt/vpnforge/sub/clients.json",
    openflux_env: dict[str, str] | None = None,
    ssh_password: str | None = None,
    xray_config: dict[str, Any] | None = None,
    hysteria_config: dict[str, Any] | None = None,
    clients_json: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Assemble group_vars/all.yml as a dict.

    Args:
      secrets: loaded Secrets document for this VPS.
      cert: parsed CertInfo (None if hysteria2 disabled).
      runtime: "native" or "docker".
      certificate_source: "upload" or files already present on "vps".
      fullchain_b64 / privkey_b64: base64 PEM files for upload mode.
      clients_json_path: where sub_server reads clients.json on the VPS.
      openflux_env: extra env vars for the openflux service unit.
      ssh_password: passed through for convenience so caller doesn't have to
        merge it into extra_vars separately. If set, becomes part of group_vars
        BUT the file is short-lived (see module docstring).
    """
    if runtime not in ("native", "docker"):
        raise InventoryError(f"unknown runtime: {runtime!r}")

    if secrets.protocols.hysteria2:
        if certificate_source not in ("upload", "vps"):
            raise InventoryError(f"unknown certificate source: {certificate_source!r}")
        if certificate_source == "upload":
            if fullchain_b64 is None or privkey_b64 is None:
                raise InventoryError(
                    "hysteria2 is enabled but fullchain_b64 / privkey_b64 not provided"
                )
            if cert is None:
                raise InventoryError("hysteria2 requires parsed CertInfo")
        elif not vps_fullchain_path or not vps_privkey_path:
            raise InventoryError("hysteria2 requires certificate paths on VPS")
        if secrets.domain is None:
            raise InventoryError("hysteria2 requires secrets.domain")

    gv: dict[str, Any] = {
        "vpnforge": {
            "runtime": runtime,
            "server_ip": secrets.ip,
            "server_domain": secrets.domain,
            "clients_json_path": clients_json_path,
            "subscription_scheme": "https"
            if secrets.protocols.hysteria2
            else "http",
            "subscription_port": 8444 if secrets.protocols.hysteria2 else 8080,
        },
        "protocols": {
            "hysteria2": secrets.protocols.hysteria2,
            "vless_reality": secrets.protocols.vless_reality,
            "openflux": secrets.protocols.openflux,
        },
    }

    if secrets.protocols.vless_reality:
        if secrets.reality is None:
            raise InventoryError("vless_reality enabled but reality config missing")
        gv["reality"] = {
            "private_key": secrets.reality.private_key,
            "public_key": secrets.reality.public_key,
            "short_id": secrets.reality.short_id,
            "dest": secrets.reality.dest,
            "server_name": secrets.reality.server_name,
            "fingerprint": secrets.reality.fingerprint,
            "spider_x": secrets.reality.spider_x,
            "xhttp_path": secrets.reality.xhttp_path,
            "xhttp_mode": secrets.reality.xhttp_mode,
        }

    if secrets.protocols.hysteria2:
        if secrets.hysteria2 is None:
            raise InventoryError("hysteria2 enabled but hysteria2 config missing")
        gv["hysteria2"] = {
            "obfs_password": secrets.hysteria2.obfs_password,
            "masquerade_url": secrets.hysteria2.masquerade_url,
            "certificate_source": certificate_source,
            "fullchain_b64": fullchain_b64,
            "privkey_b64": privkey_b64,
            "vps_fullchain_path": vps_fullchain_path,
            "vps_privkey_path": vps_privkey_path,
        }
        if cert is not None:
            gv["cert"] = {
                "not_after": cert.not_after.isoformat(),
                "issuer_cn": cert.issuer_cn,
                "sha256": cert.sha256,
            }

    if secrets.protocols.openflux:
        # argv is pre-rendered here so the systemd template stays dumb.
        # build_exit_node_argv raises OpenFluxError on invalid combos
        # (e.g. yandex without url) — let it propagate.
        gv["openflux"] = {
            "transport": secrets.openflux.transport,
            "mode": secrets.openflux.mode,
            "codec": secrets.openflux.codec,
            "local_ip": secrets.openflux.local_ip,
            "yandex_url": secrets.openflux.yandex_url,
            "max_token": secrets.openflux.max_token,
            "max_uid": secrets.openflux.max_uid,
            "encryption_key": secrets.openflux.encryption_key,
            "session_b64": secrets.openflux.session_b64,
            "debug": secrets.openflux.debug,
            "argv": build_exit_node_argv(secrets),
            "env": dict(openflux_env or {}),
        }

    if ssh_password:
        # Only for the duration of one deploy; file is removed afterwards.
        gv["ansible_password"] = ssh_password

    if xray_config is not None:
        gv["xray_config"] = xray_config
    if hysteria_config is not None:
        gv["hysteria_config"] = hysteria_config
    if clients_json is not None:
        gv["clients_json"] = clients_json

    return gv


# ---------- serialization ----------


def dump_group_vars(gv: dict[str, Any]) -> str:
    """Deterministic YAML dump for golden tests and for writing to disk."""
    dumped = yaml.safe_dump(
        gv,
        default_flow_style=False,
        allow_unicode=True,
        sort_keys=False,
    )
    return cast(str, dumped)


# ---------- small helpers for main.py ----------


def encode_pem_b64(path_or_bytes: str | bytes) -> str:
    """Read a PEM file (or bytes) and return base64 text.

    Kept here so main.py has one place to call, and tests can assert
    roundtrip without duplicating base64 logic.
    """
    if isinstance(path_or_bytes, bytes):
        raw = path_or_bytes
    else:
        with open(path_or_bytes, "rb") as fh:
            raw = fh.read()
    return base64.b64encode(raw).decode("ascii")
