"""Pydantic models for secrets, clients, and API payloads."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator


def _utcnow() -> datetime:
    return datetime.now(UTC)


# ---------- protocols ----------


class ProtocolFlags(BaseModel):
    model_config = ConfigDict(extra="forbid")

    hysteria2: bool = False
    vless_reality: bool = False
    openflux: bool = False


OpenFluxTransport = Literal["cupsonline", "yandex", "oneme"]
OpenFluxMode = Literal["proxy", "raw"]


class OpenFluxConfig(BaseModel):
    """OpenFlux exit-node configuration.

    Upstream: https://github.com/p1neappleXpress/OpenFlux

    Fields mirror the CLI flags of `universal-bypass-tool`:
      * transport    -> --transport
      * mode         -> --mode
      * local_ip     -> --local-ip (raw mode only)
      * yandex_url   -> --url      (yandex transport only)
      * max_token    -> --maxToken (oneme transport only)
      * max_uid      -> --maxUid   (oneme transport only)
      * debug        -> --debug
    `encryption_key` is AES-256 material we generate; Ansible writes it
    to /etc/vpnforge/openflux.key and the service uses --encryption-key-file.
    """

    model_config = ConfigDict(extra="forbid")

    transport: OpenFluxTransport = "cupsonline"
    mode: OpenFluxMode = "proxy"
    local_ip: str | None = None
    yandex_url: str | None = None
    max_token: str | None = None
    max_uid: str | None = None
    encryption_key: str | None = None
    session_b64: str | None = None
    debug: bool = False


class RealityConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    private_key: str
    public_key: str
    short_id: str
    dest: str = "www.microsoft.com:443"
    server_name: str = "www.microsoft.com"
    fingerprint: str = "chrome"
    spider_x: str = "/"
    xhttp_path: str = "/"
    xhttp_mode: Literal["packet-up", "stream-up", "stream-one"] = "packet-up"


class Hysteria2Config(BaseModel):
    model_config = ConfigDict(extra="forbid")

    obfs_password: str
    masquerade_url: str = "https://apple.com"


class Client(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    label: str
    created_at: datetime = Field(default_factory=_utcnow)
    sub_token: str
    vless_uuid: str
    hysteria_user: str
    hysteria_pass: str
    disabled: bool = False

    @field_validator("label")
    @classmethod
    def _label_not_empty(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("label must not be empty")
        return v


class CloudflareState(BaseModel):
    model_config = ConfigDict(extra="forbid")

    zone_id: str | None = None
    record_id: str | None = None


class CertState(BaseModel):
    model_config = ConfigDict(extra="forbid")

    not_after: datetime | None = None
    issuer: str | None = None
    sha256: str | None = None


class Secrets(BaseModel):
    """Root document persisted to data/secrets/<ip>.json."""

    model_config = ConfigDict(extra="forbid")

    version: int = 1
    ip: str
    domain: str | None = None
    created_at: datetime = Field(default_factory=_utcnow)
    updated_at: datetime = Field(default_factory=_utcnow)

    protocols: ProtocolFlags = Field(default_factory=ProtocolFlags)
    openflux: OpenFluxConfig = Field(default_factory=OpenFluxConfig)
    reality: RealityConfig | None = None
    hysteria2: Hysteria2Config | None = None

    clients: list[Client] = Field(default_factory=list)
    cloudflare: CloudflareState = Field(default_factory=CloudflareState)
    cert: CertState = Field(default_factory=CertState)


# ---------- API DTOs ----------


class CertInfo(BaseModel):
    """Parsed X.509 certificate info (result of cert_validator)."""

    model_config = ConfigDict(extra="forbid")

    subject_cn: str
    san_domains: list[str]
    not_before: datetime
    not_after: datetime
    issuer_cn: str
    sha256: str


class VPSConnection(BaseModel):
    """SSH connection parameters for the target VPS."""

    model_config = ConfigDict(extra="forbid")

    ip: str
    ssh_user: str = "root"
    ssh_port: int = 22
    ssh_private_key_path: str | None = None
    ssh_password: str | None = None


RuntimeKind = Literal["native", "docker"]


class ErrorBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    code: str
    message: str


class ErrorResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    error: ErrorBody


class DnsUpsertRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    fqdn: str
    ip: str
    root_domain: str | None = None
    zone_id: str | None = None
    api_token: str | None = None


class SecretsIpRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    ip: str


class ClientCreateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    ip: str
    label: str


class ClientPatchRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    ip: str
    label: str | None = None
    disabled: bool | None = None


class ClientRotateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    ip: str


class DeployRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    ip: str
    ssh_user: str = "root"
    ssh_port: int = 22
    ssh_private_key_path: str | None = None
    ssh_password: str | None = None
    domain: str | None = None
    root_domain: str | None = None
    protocols: ProtocolFlags
    runtime: RuntimeKind = "native"
    openflux: OpenFluxConfig | None = None
    cf_api_token: str | None = None

    @field_validator("protocols")
    @classmethod
    def _at_least_one_protocol(cls, v: ProtocolFlags) -> ProtocolFlags:
        if not (v.hysteria2 or v.vless_reality or v.openflux):
            raise ValueError("at least one protocol must be enabled")
        return v
