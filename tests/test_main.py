"""Tests for FastAPI control plane and VPS sub-server."""

from __future__ import annotations

import asyncio
import datetime as dt
import json
from pathlib import Path
from typing import Any

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from httpx import ASGITransport, AsyncClient

from vpnforge.config import Settings
from vpnforge.main import DeployJob, create_app
from vpnforge.models import OpenFluxConfig, ProtocolFlags, RealityConfig, Secrets
from vpnforge.secrets_store import SecretsStore
from vpnforge.vps_sub_server.app import app as sub_app

# ---------- fake ansible / CF ----------


class FakeAnsibleRun:
    def __init__(
        self,
        lines: list[str] | None = None,
        returncode: int = 0,
        timed_out: bool = False,
    ) -> None:
        self._lines = lines or ["PLAY [vpn]", "ok: [1.2.3.4]"]
        self.returncode = returncode
        self.timed_out = timed_out
        self.tail = "\n".join(self._lines[-5:])

    async def __aiter__(self):  # type: ignore[no-untyped-def]
        for line in self._lines:
            yield line


class FakeRunner:
    def __init__(self, run: FakeAnsibleRun | None = None) -> None:
        self._run = run or FakeAnsibleRun()
        self.calls: list[tuple[Path, Path]] = []

    async def run(
        self,
        playbook: Path,
        inventory: Path,
        extra_vars: dict[str, Any] | None = None,
        extra_vars_file: Path | None = None,
    ) -> FakeAnsibleRun:
        self.calls.append((playbook, inventory))
        return self._run


class FakeCF:
    def __init__(self, token: str) -> None:
        self.token = token

    def resolve_zone_id(self, root_domain: str) -> str:
        return "zone-1"

    def upsert_a_record(
        self,
        zone_id: str,
        fqdn: str,
        ip: str,
        ttl: int = 60,
        proxied: bool = False,
    ) -> str:
        return "rec-1"


# ---------- cert helper ----------


def _write_valid_cert(tmp_path: Path) -> tuple[Path, Path]:
    now = dt.datetime(2026, 9, 14, 12, 0, 0, tzinfo=dt.UTC)
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "node1.example.com")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(days=1))
        .not_valid_after(now + dt.timedelta(days=89))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName("node1.example.com")]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    fullchain = tmp_path / "fullchain.pem"
    privkey = tmp_path / "privkey.pem"
    fullchain.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    privkey.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    return fullchain, privkey


TEST_PASSWORD = "testpass"


async def _authenticate(client: AsyncClient) -> None:
    response = await client.post(
        "/login",
        data={
            "profile": "Тестовый профиль",
            "password": TEST_PASSWORD,
            "confirmation": TEST_PASSWORD,
            "setup": "true",
        },
    )
    assert response.status_code == 303, response.text


@pytest.fixture()
async def client_app(tmp_path: Path) -> Any:
    settings = Settings(data_dir=tmp_path / "data", cf_api_token="cf-token")
    runner = FakeRunner()
    app = create_app(
        settings=settings,
        runner=runner,  # type: ignore[arg-type]
        cf_factory=lambda token: FakeCF(token),
    )
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://127.0.0.1") as ac:
        await _authenticate(ac)
        yield ac, app, runner


async def _wait_job(app: Any, job_id: str, timeout: float = 5.0) -> DeployJob:
    job: DeployJob = app.state.ctx.jobs[job_id]
    await asyncio.wait_for(job.done.wait(), timeout=timeout)
    return job


# ---------- health / cert / dns ----------


async def test_health(client_app: Any) -> None:
    ac, _, _ = client_app
    r = await ac.get("/api/health")
    assert r.status_code == 200
    assert r.json() == {"status": "ok"}


async def test_local_profile_login_and_logout(tmp_path: Path) -> None:
    settings = Settings(data_dir=tmp_path / "data")
    app = create_app(settings=settings)
    base_url = "http://127.0.0.1"
    async with AsyncClient(transport=ASGITransport(app=app), base_url=base_url) as ac:
        response = await ac.get("/", cookies={"bypass_profile": "legacy"})
        assert response.status_code == 303
        assert response.headers["location"] == "/login"
        assert (await ac.get("/api/clients", params={"ip": "192.0.2.1"})).status_code == 401
        assert (await ac.get("/api/health")).status_code == 200
        assert "Создайте профиль" in (await ac.get("/login")).text
        assert (await ac.post("/login", data={"profile": " "})).status_code == 422
        assert (await ac.post(
            "/login",
            headers={"origin": "http://example.test"},
            data={"profile": "Тестовый профиль"},
        )).status_code == 403

        await _authenticate(ac)
        token = ac.cookies["bypass_session"]
        assert TEST_PASSWORD.encode() not in (settings.data_dir / "auth/auth.sqlite3").read_bytes()
        assert token.encode() not in (settings.data_dir / "auth/auth.sqlite3").read_bytes()
        dashboard = await ac.get("/")
        assert dashboard.status_code == 200
        assert 'data-profile="Тестовый профиль"' in dashboard.text
        assert dashboard.headers["cache-control"] == "no-store"

    restarted = create_app(settings=settings)
    async with AsyncClient(transport=ASGITransport(app=restarted), base_url=base_url) as ac:
        ac.cookies.set("bypass_session", token)
        assert (await ac.get("/")).status_code == 200
        assert (await ac.post("/logout")).headers["location"] == "/login"
        ac.cookies.set("bypass_session", token)
        assert (await ac.get("/")).status_code == 303
        ac.cookies.clear()
        assert "Введите имя профиля и пароль." in (await ac.get("/login")).text

        invalid = await ac.post(
            "/login", data={"profile": "Тестовый профиль", "password": "incorrect-password"}
        )
        assert invalid.status_code == 401
        assert "bypass_session" not in ac.cookies

        valid = await ac.post(
            "/login", data={"profile": "тестовый профиль", "password": TEST_PASSWORD}
        )
        assert valid.headers["location"] == "/"
        assert "HttpOnly" in valid.headers["set-cookie"]
        assert "SameSite=strict" in valid.headers["set-cookie"]
        assert ac.cookies["bypass_session"] != token


async def test_clients_list_before_first_deploy_is_empty(client_app: Any) -> None:
    ac, _, _ = client_app
    response = await ac.get("/api/clients", params={"ip": "88.214.54.179"})
    assert response.status_code == 200
    assert response.json() == []


async def test_cert_validate(client_app: Any, tmp_path: Path) -> None:
    ac, _, _ = client_app
    fc, pk = _write_valid_cert(tmp_path)
    r = await ac.post(
        "/api/cert/validate",
        files={
            "fullchain": ("fullchain.pem", fc.read_bytes(), "application/x-pem-file"),
            "privkey": ("privkey.pem", pk.read_bytes(), "application/x-pem-file"),
        },
        data={"domain": "node1.example.com"},
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["subject_cn"] == "node1.example.com"


async def test_cert_validate_bad_file(client_app: Any) -> None:
    ac, _, _ = client_app
    r = await ac.post(
        "/api/cert/validate",
        files={
            "fullchain": ("fullchain.pem", b"nope", "application/x-pem-file"),
            "privkey": ("privkey.pem", b"nope", "application/x-pem-file"),
        },
    )
    assert r.status_code == 400
    assert r.json()["error"]["code"] == "cert_error"


async def test_dns_upsert(client_app: Any) -> None:
    ac, _, _ = client_app
    r = await ac.post(
        "/api/dns/upsert",
        json={"fqdn": "node1.example.com", "ip": "1.2.3.4"},
    )
    assert r.status_code == 200
    assert r.json() == {"zone_id": "zone-1", "record_id": "rec-1"}


async def test_dns_upsert_no_token(tmp_path: Path) -> None:
    settings = Settings(data_dir=tmp_path / "data", cf_api_token="")
    app = create_app(
        settings=settings,
        runner=FakeRunner(),  # type: ignore[arg-type]
        cf_factory=lambda token: FakeCF(token),
    )
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://127.0.0.1") as ac:
        await _authenticate(ac)
        r = await ac.post(
            "/api/dns/upsert",
            json={"fqdn": "node1.example.com", "ip": "1.2.3.4"},
        )
    assert r.status_code == 401
    assert r.json()["error"]["code"] == "cf_auth"


# ---------- secrets / clients ----------


async def test_secrets_and_clients_crud(client_app: Any) -> None:
    ac, app, _ = client_app
    store: SecretsStore = app.state.ctx.store
    store.save(Secrets(ip="1.2.3.4", protocols=ProtocolFlags(vless_reality=True)))

    r = await ac.post("/api/secrets/load", json={"ip": "1.2.3.4"})
    assert r.status_code == 200
    assert r.json()["ip"] == "1.2.3.4"

    r = await ac.post("/api/clients", json={"ip": "1.2.3.4", "label": "Вася"})
    assert r.status_code == 200
    cid = r.json()["id"]
    token = r.json()["sub_token"]

    r = await ac.get("/api/clients", params={"ip": "1.2.3.4"})
    assert r.status_code == 200
    assert len(r.json()) == 1

    r = await ac.patch(
        f"/api/clients/{cid}",
        json={"ip": "1.2.3.4", "label": "Петя", "disabled": True},
    )
    assert r.status_code == 200
    assert r.json()["label"] == "Петя"
    assert r.json()["disabled"] is True

    r = await ac.get(f"/api/sub/{token}")
    assert r.status_code == 404

    r = await ac.patch(
        f"/api/clients/{cid}",
        json={"ip": "1.2.3.4", "disabled": False},
    )
    assert r.json()["disabled"] is False

    r = await ac.get(f"/api/sub/{token}")
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/plain")

    r = await ac.post("/api/clients/rotate", json={"ip": "1.2.3.4"})
    assert r.status_code == 200
    new_token = r.json()[0]["sub_token"]
    assert new_token != token

    r = await ac.delete(f"/api/clients/{cid}", params={"ip": "1.2.3.4"})
    assert r.status_code == 200
    r = await ac.get("/api/clients", params={"ip": "1.2.3.4"})
    assert r.json() == []


async def test_secrets_export_import(client_app: Any) -> None:
    ac, app, _ = client_app
    store: SecretsStore = app.state.ctx.store
    store.save(Secrets(ip="1.2.3.4", protocols=ProtocolFlags(vless_reality=True)))

    r = await ac.post("/api/secrets/export", json={"ip": "1.2.3.4"})
    assert r.status_code == 200
    raw = r.content

    store.delete("1.2.3.4")
    r = await ac.post(
        "/api/secrets/import",
        data={"ip": "1.2.3.4"},
        files={"file": ("secrets.json", raw, "application/json")},
    )
    assert r.status_code == 200
    assert r.json()["ip"] == "1.2.3.4"


async def test_secrets_load_missing(client_app: Any) -> None:
    ac, _, _ = client_app
    r = await ac.post("/api/secrets/load", json={"ip": "9.9.9.9"})
    assert r.status_code == 404
    assert r.json()["error"]["code"] == "secrets_not_found"


async def test_clients_conflict(client_app: Any) -> None:
    ac, app, _ = client_app
    app.state.ctx.store.save(
        Secrets(ip="1.2.3.4", protocols=ProtocolFlags(vless_reality=True))
    )
    await ac.post("/api/clients", json={"ip": "1.2.3.4", "label": "A"})
    r = await ac.post("/api/clients", json={"ip": "1.2.3.4", "label": "A"})
    assert r.status_code == 409


async def test_client_patch_empty(client_app: Any) -> None:
    ac, app, _ = client_app
    app.state.ctx.store.save(
        Secrets(ip="1.2.3.4", protocols=ProtocolFlags(vless_reality=True))
    )
    r = await ac.post("/api/clients", json={"ip": "1.2.3.4", "label": "A"})
    cid = r.json()["id"]
    r = await ac.patch(f"/api/clients/{cid}", json={"ip": "1.2.3.4"})
    assert r.status_code == 422


async def test_sub_unknown_token(client_app: Any) -> None:
    ac, _, _ = client_app
    r = await ac.get("/api/sub/deadbeef")
    assert r.status_code == 404


async def test_xray_config_has_ru_direct_routing(client_app: Any) -> None:
    ac, app, _ = client_app
    store: SecretsStore = app.state.ctx.store
    secrets = Secrets(
        ip="1.2.3.4",
        protocols=ProtocolFlags(vless_reality=True),
        reality=RealityConfig(
            private_key="private",
            public_key="public",
            short_id="deadbeef",
        ),
    )
    store.save(secrets)
    created = await ac.post("/api/clients", json={"ip": "1.2.3.4", "label": "Phone"})
    token = created.json()["sub_token"]

    response = await ac.get(f"/api/config/{token}/xray.json")

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/json")
    rules = response.json()["routing"]["rules"]
    assert any(rule.get("domain") == ["geosite:category-ru"] for rule in rules)
    assert any(rule.get("ip") == ["geoip:ru"] for rule in rules)


async def test_openflux_client_setup_uses_saved_session(client_app: Any) -> None:
    ac, app, _ = client_app
    app.state.ctx.store.save(
        Secrets(
            ip="1.2.3.4",
            protocols=ProtocolFlags(openflux=True),
            openflux=OpenFluxConfig(
                transport="cupsonline",
                session_b64="c2Vzc2lvbi1kYXRhLWZvci1jbGllbnQ=",
                encryption_key="shared-secret",
            ),
        )
    )

    response = await ac.get("/api/openflux/client", params={"ip": "1.2.3.4"})

    assert response.status_code == 200
    assert "--role client" in response.json()["command"]
    assert "--codec batched" in response.json()["command"]
    assert response.json()["encryption_key"] == "shared-secret"


# ---------- deploy ----------


async def test_deploy_vless_only(client_app: Any) -> None:
    ac, app, runner = client_app
    payload = json.dumps(
        {
            "ip": "1.2.3.4",
            "protocols": {
                "hysteria2": False,
                "vless_reality": True,
                "openflux": False,
            },
            "ssh_private_key_path": "/tmp/id_ed25519",
        }
    )
    r = await ac.post("/api/deploy", data={"payload": payload})
    assert r.status_code == 202, r.text
    job_id = r.json()["job_id"]
    job = await _wait_job(app, job_id)
    assert job.status == "success"
    assert runner.calls
    secrets = app.state.ctx.store.load("1.2.3.4")
    assert secrets.reality is not None
    assert secrets.clients[0].label == "default"
    assert secrets.reality.private_key  # persisted, not empty
    assert secrets.reality.dest == "www.apple.com:443"
    assert secrets.reality.server_name == "www.apple.com"


async def test_deploy_does_not_rotate_keys(client_app: Any) -> None:
    ac, app, _ = client_app
    payload = json.dumps(
        {
            "ip": "1.2.3.4",
            "protocols": {
                "hysteria2": False,
                "vless_reality": True,
                "openflux": False,
            },
        }
    )
    r = await ac.post("/api/deploy", data={"payload": payload})
    job = await _wait_job(app, r.json()["job_id"])
    assert job.status == "success"
    first = app.state.ctx.store.load("1.2.3.4").reality
    assert first is not None
    r = await ac.post("/api/deploy", data={"payload": payload})
    job = await _wait_job(app, r.json()["job_id"])
    assert job.status == "success"
    second = app.state.ctx.store.load("1.2.3.4").reality
    assert second is not None
    assert first.private_key == second.private_key
    assert first.public_key == second.public_key


async def test_deploy_migrates_old_reality_target_without_rotating_keys(
    client_app: Any,
) -> None:
    ac, app, _ = client_app
    secrets = Secrets(
        ip="1.2.3.4",
        protocols=ProtocolFlags(vless_reality=True),
        reality=RealityConfig(
            private_key="existing-private-key",
            public_key="existing-public-key",
            short_id="deadbeef",
            dest="www.microsoft.com:443",
            server_name="www.microsoft.com",
        ),
    )
    app.state.ctx.store.save(secrets)
    payload = json.dumps(
        {"ip": "1.2.3.4", "protocols": {"vless_reality": True}}
    )
    response = await ac.post("/api/deploy", data={"payload": payload})
    job = await _wait_job(app, response.json()["job_id"])
    assert job.status == "success"
    reality = app.state.ctx.store.load("1.2.3.4").reality
    assert reality is not None
    assert reality.dest == "www.apple.com:443"
    assert reality.server_name == "www.apple.com"
    assert reality.private_key == "existing-private-key"
    assert reality.public_key == "existing-public-key"
    assert reality.short_id == "deadbeef"


async def test_deploy_hysteria_needs_certs(client_app: Any) -> None:
    ac, _, _ = client_app
    payload = json.dumps(
        {
            "ip": "1.2.3.4",
            "domain": "node1.example.com",
            "protocols": {
                "hysteria2": True,
                "vless_reality": False,
                "openflux": False,
            },
        }
    )
    r = await ac.post("/api/deploy", data={"payload": payload})
    assert r.status_code == 422


async def test_deploy_hysteria_with_certs(client_app: Any, tmp_path: Path) -> None:
    ac, app, _ = client_app
    fc, pk = _write_valid_cert(tmp_path)
    payload = json.dumps(
        {
            "ip": "1.2.3.4",
            "domain": "node1.example.com",
            "protocols": {
                "hysteria2": True,
                "vless_reality": False,
                "openflux": False,
            },
        }
    )
    r = await ac.post(
        "/api/deploy",
        data={"payload": payload},
        files={
            "fullchain": ("fullchain.pem", fc.read_bytes(), "application/x-pem-file"),
            "privkey": ("privkey.pem", pk.read_bytes(), "application/x-pem-file"),
        },
    )
    assert r.status_code == 202, r.text
    job = await _wait_job(app, r.json()["job_id"])
    assert job.status == "success"
    secrets = app.state.ctx.store.load("1.2.3.4")
    assert secrets.hysteria2 is not None
    assert secrets.cloudflare.zone_id == "zone-1"
    assert secrets.cert.sha256


async def test_deploy_hysteria_with_existing_vps_certs(client_app: Any) -> None:
    ac, app, _ = client_app
    payload = json.dumps(
        {
            "ip": "1.2.3.4",
            "domain": "node1.example.com",
            "certificate_source": "vps",
            "vps_fullchain_path": "/etc/letsencrypt/live/node1.example.com/fullchain.pem",
            "vps_privkey_path": "/etc/letsencrypt/live/node1.example.com/privkey.pem",
            "protocols": {
                "hysteria2": True,
                "vless_reality": False,
                "openflux": False,
            },
        }
    )
    response = await ac.post("/api/deploy", data={"payload": payload})
    assert response.status_code == 202, response.text
    job = await _wait_job(app, response.json()["job_id"])
    assert job.status == "success"


@pytest.mark.parametrize(
    ("fullchain_path", "privkey_path"),
    [
        (None, "/etc/letsencrypt/live/node1.example.com/privkey.pem"),
        ("relative/fullchain.pem", "/etc/letsencrypt/live/node1.example.com/privkey.pem"),
    ],
)
async def test_deploy_hysteria_rejects_bad_vps_cert_paths(
    client_app: Any,
    fullchain_path: str | None,
    privkey_path: str,
) -> None:
    ac, _, _ = client_app
    payload = json.dumps(
        {
            "ip": "1.2.3.4",
            "domain": "node1.example.com",
            "certificate_source": "vps",
            "vps_fullchain_path": fullchain_path,
            "vps_privkey_path": privkey_path,
            "protocols": {
                "hysteria2": True,
                "vless_reality": False,
                "openflux": False,
            },
        }
    )
    response = await ac.post("/api/deploy", data={"payload": payload})
    assert response.status_code == 422


async def test_deploy_openflux_parses_session(tmp_path: Path) -> None:
    session = (
        "eyJyb29tcyI6WyIwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAiXX0="  # {"rooms":["000..."]}
    )
    # ensure min 16 decoded bytes — pad rooms list
    import base64

    raw = json.dumps({"rooms": ["a" * 24]}).encode()
    session = base64.b64encode(raw).decode()
    lines = [
        "=== COPY THIS TO CLIENT ===",
        session,
        "===========================",
    ]
    runner = FakeRunner(FakeAnsibleRun(lines=lines))
    settings = Settings(data_dir=tmp_path / "data", cf_api_token="cf-token")
    app = create_app(
        settings=settings,
        runner=runner,  # type: ignore[arg-type]
        cf_factory=lambda token: FakeCF(token),
    )
    transport = ASGITransport(app=app)
    payload = json.dumps(
        {
            "ip": "1.2.3.4",
            "protocols": {
                "hysteria2": False,
                "vless_reality": False,
                "openflux": True,
            },
            "openflux": {"transport": "cupsonline", "mode": "proxy"},
        }
    )
    async with AsyncClient(transport=transport, base_url="http://127.0.0.1") as ac:
        await _authenticate(ac)
        r = await ac.post("/api/deploy", data={"payload": payload})
        job = await _wait_job(app, r.json()["job_id"])
    assert job.status == "success"
    secrets = app.state.ctx.store.load("1.2.3.4")
    assert secrets.openflux.session_b64 == session
    assert secrets.openflux.encryption_key


async def test_deploy_ansible_failure(tmp_path: Path) -> None:
    runner = FakeRunner(FakeAnsibleRun(returncode=2, lines=["fatal"]))
    settings = Settings(data_dir=tmp_path / "data")
    app = create_app(
        settings=settings,
        runner=runner,  # type: ignore[arg-type]
        cf_factory=lambda token: FakeCF(token),
    )
    transport = ASGITransport(app=app)
    payload = json.dumps(
        {
            "ip": "1.2.3.4",
            "protocols": {
                "hysteria2": False,
                "vless_reality": True,
                "openflux": False,
            },
        }
    )
    async with AsyncClient(transport=transport, base_url="http://127.0.0.1") as ac:
        await _authenticate(ac)
        r = await ac.post("/api/deploy", data={"payload": payload})
        job = await _wait_job(app, r.json()["job_id"])
        stream = await ac.get(f"/api/deploy/stream/{r.json()['job_id']}")
    assert job.status == "failed"
    assert stream.status_code == 200
    assert "fatal" in stream.text or "ansible" in stream.text


async def test_deploy_stream_unknown(client_app: Any) -> None:
    ac, _, _ = client_app
    r = await ac.get("/api/deploy/stream/nope")
    assert r.status_code == 404


def test_deploy_job_serializes_log_events_for_frontend() -> None:
    job = DeployJob(job_id="job-1")
    job.emit("log", "проверка подключения")
    assert json.loads(job.history[0]["data"]) == {"line": "проверка подключения"}


async def test_deploy_invalid_payload(client_app: Any) -> None:
    ac, _, _ = client_app
    r = await ac.post("/api/deploy", data={"payload": "{"})
    assert r.status_code == 422


async def test_deploy_no_protocols(client_app: Any) -> None:
    ac, _, _ = client_app
    payload = json.dumps(
        {
            "ip": "1.2.3.4",
            "protocols": {
                "hysteria2": False,
                "vless_reality": False,
                "openflux": False,
            },
        }
    )
    r = await ac.post("/api/deploy", data={"payload": payload})
    assert r.status_code == 422


async def test_validation_error_shape(client_app: Any) -> None:
    ac, _, _ = client_app
    r = await ac.post("/api/clients", json={})
    assert r.status_code == 422
    assert "error" in r.json()
    assert r.json()["error"]["code"] == "validation_error"


# ---------- vps sub-server ----------


async def test_vps_sub_health() -> None:
    transport = ASGITransport(app=sub_app)
    async with AsyncClient(transport=transport, base_url="http://127.0.0.1") as ac:
        r = await ac.get("/health")
    assert r.status_code == 200
    assert r.json() == {"status": "ok"}


async def test_vps_sub_found_and_missing(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    clients = {
        "version": 1,
        "clients": [
            {
                "id": "c1",
                "label": "Вася",
                "sub_token": "aa" * 16,
                "urls": ["vless://x", "hysteria2://y"],
                "xray_config": {"routing": {"rules": []}},
            }
        ],
    }
    p = tmp_path / "clients.json"
    p.write_text(json.dumps(clients), encoding="utf-8")
    monkeypatch.setattr("vpnforge.vps_sub_server.app.CLIENTS_FILE", p)

    transport = ASGITransport(app=sub_app)
    async with AsyncClient(transport=transport, base_url="http://127.0.0.1") as ac:
        r = await ac.get(f"/sub/{'aa' * 16}")
        assert r.status_code == 200
        assert r.headers["content-type"].startswith("text/plain")
        import base64

        decoded = base64.b64decode(r.text).decode()
        assert "vless://x" in decoded
        profile = await ac.get(f"/config/{'aa' * 16}/xray.json")
        assert profile.status_code == 200
        assert profile.json()["routing"]["rules"] == []
        missing = await ac.get("/sub/not-a-token")
        assert missing.status_code == 404


async def test_vps_sub_missing_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "vpnforge.vps_sub_server.app.CLIENTS_FILE", tmp_path / "nope.json"
    )
    transport = ASGITransport(app=sub_app)
    async with AsyncClient(transport=transport, base_url="http://127.0.0.1") as ac:
        r = await ac.get("/sub/token")
    assert r.status_code == 503
