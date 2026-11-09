"""FastAPI control plane and local web UI for bypass."""

from __future__ import annotations

import asyncio
import json
import logging
import os
import shutil
import tempfile
import uuid
from collections.abc import AsyncIterator, Callable
from contextlib import suppress
from dataclasses import dataclass, field
from pathlib import Path

from fastapi import FastAPI, File, Form, HTTPException, Query, Request, UploadFile
from fastapi.exceptions import RequestValidationError
from fastapi.responses import (
    HTMLResponse,
    JSONResponse,
    PlainTextResponse,
    Response,
)
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import ValidationError
from sse_starlette.sse import EventSourceResponse

from vpnforge import (
    cert_validator,
    config_builder,
    crypto_utils,
    demo_deploy,
    inventory_builder,
    sub_builder,
)
from vpnforge.ansible_runner import AnsibleError, AnsibleRunner
from vpnforge.cert_validator import CertError
from vpnforge.client_manager import (
    ClientConflict,
    ClientError,
    ClientManager,
    ClientNotFound,
)
from vpnforge.config import Settings, get_settings
from vpnforge.dns_manager import CFAuthError, CFError, CFZoneNotFound, CloudflareDNS
from vpnforge.models import (
    CertInfo,
    CertState,
    Client,
    ClientCreateRequest,
    ClientPatchRequest,
    ClientRotateRequest,
    DeployRequest,
    DnsUpsertRequest,
    Hysteria2Config,
    RealityConfig,
    Secrets,
    SecretsIpRequest,
    VPSConnection,
)
from vpnforge.openflux_manager import OpenFluxError, build_client_command, parse_session_b64
from vpnforge.secrets_store import SecretsError, SecretsInvalid, SecretsNotFound, SecretsStore

logger = logging.getLogger("vpnforge")

PROJECT_ROOT = Path(__file__).resolve().parent.parent
PLAYBOOK = PROJECT_ROOT / "ansible" / "deploy.yml"
WEB_DIR = PROJECT_ROOT / "vpnforge" / "web"

CfFactory = Callable[[str], CloudflareDNS]


class ApiError(Exception):
    def __init__(self, code: str, message: str, status: int = 400) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.status = status


def _error_body(code: str, message: str, status: int) -> JSONResponse:
    return JSONResponse(
        status_code=status,
        content={"error": {"code": code, "message": message}},
    )


# ---------- jobs ----------


@dataclass
class DeployJob:
    job_id: str
    status: str = "pending"
    history: list[dict[str, str]] = field(default_factory=list)
    error: str | None = None
    done: asyncio.Event = field(default_factory=asyncio.Event)
    _queues: list[asyncio.Queue[dict[str, str] | None]] = field(default_factory=list)
    demo_task: asyncio.Task[None] | None = None

    def emit(self, event: str, data: str) -> None:
        payload = json.dumps({"line": data}, ensure_ascii=False) if event == "log" else data
        item = {"event": event, "data": payload}
        self.history.append(item)
        for q in list(self._queues):
            q.put_nowait(item)

    def finish(self, status: str, error: str | None = None) -> None:
        self.status = status
        self.error = error
        self.emit("done", json.dumps({"status": status, "error": error}))
        self.done.set()
        for q in list(self._queues):
            q.put_nowait(None)

    def subscribe(self) -> asyncio.Queue[dict[str, str] | None]:
        q: asyncio.Queue[dict[str, str] | None] = asyncio.Queue()
        for item in self.history:
            q.put_nowait(item)
        if self.done.is_set():
            q.put_nowait(None)
        else:
            self._queues.append(q)
        return q


# ---------- app factory ----------


class AppContext:
    def __init__(
        self,
        settings: Settings,
        store: SecretsStore,
        clients: ClientManager,
        runner: AnsibleRunner,
        cf_factory: CfFactory,
    ) -> None:
        self.settings = settings
        self.store = store
        self.clients = clients
        self.runner = runner
        self.cf_factory = cf_factory
        self.jobs: dict[str, DeployJob] = {}


def create_app(
    *,
    settings: Settings | None = None,
    store: SecretsStore | None = None,
    runner: AnsibleRunner | None = None,
    cf_factory: CfFactory | None = None,
) -> FastAPI:
    settings = settings or get_settings()
    store = store or SecretsStore(settings.secrets_dir)
    clients = ClientManager(store)
    runner = runner or AnsibleRunner(
        PROJECT_ROOT,
        ansible_bin=settings.ansible_bin,
        timeout=float(settings.ansible_timeout),
    )
    cf_factory = cf_factory or (lambda token: CloudflareDNS(token))
    ctx = AppContext(settings, store, clients, runner, cf_factory)

    app = FastAPI(title="bypass", docs_url=None, redoc_url=None)
    app.state.ctx = ctx

    # Mount static files
    app.mount("/static", StaticFiles(directory=str(WEB_DIR / "static")), name="static")

    # Setup templates
    templates = Jinja2Templates(directory=str(WEB_DIR / "templates"))

    @app.exception_handler(ApiError)
    async def _api_err(_request: Request, exc: ApiError) -> JSONResponse:
        return _error_body(exc.code, exc.message, exc.status)

    @app.exception_handler(RequestValidationError)
    async def _validation_handler(
        _request: Request, exc: RequestValidationError
    ) -> JSONResponse:
        return _error_body("validation_error", str(exc.errors()), 422)

    @app.exception_handler(SecretsNotFound)
    async def _secrets_nf(_request: Request, exc: SecretsNotFound) -> JSONResponse:
        return _error_body("secrets_not_found", str(exc), 404)

    @app.exception_handler(SecretsInvalid)
    async def _secrets_inv(_request: Request, exc: SecretsInvalid) -> JSONResponse:
        return _error_body("secrets_invalid", str(exc), 400)

    @app.exception_handler(SecretsError)
    async def _secrets_err(_request: Request, exc: SecretsError) -> JSONResponse:
        return _error_body("secrets_error", str(exc), 400)

    @app.exception_handler(ClientNotFound)
    async def _client_nf(_request: Request, exc: ClientNotFound) -> JSONResponse:
        return _error_body("client_not_found", str(exc), 404)

    @app.exception_handler(ClientConflict)
    async def _client_cf(_request: Request, exc: ClientConflict) -> JSONResponse:
        return _error_body("client_conflict", str(exc), 409)

    @app.exception_handler(ClientError)
    async def _client_err(_request: Request, exc: ClientError) -> JSONResponse:
        return _error_body("client_error", str(exc), 400)

    @app.exception_handler(CertError)
    async def _cert_err(_request: Request, exc: CertError) -> JSONResponse:
        return _error_body("cert_error", str(exc), 400)

    @app.exception_handler(CFAuthError)
    async def _cf_auth(_request: Request, exc: CFAuthError) -> JSONResponse:
        return _error_body("cf_auth", str(exc), 401)

    @app.exception_handler(CFZoneNotFound)
    async def _cf_zone(_request: Request, exc: CFZoneNotFound) -> JSONResponse:
        return _error_body("cf_zone_not_found", str(exc), 404)

    @app.exception_handler(CFError)
    async def _cf_err(_request: Request, exc: CFError) -> JSONResponse:
        return _error_body("cf_error", str(exc), 400)

    @app.exception_handler(OpenFluxError)
    async def _of_err(_request: Request, exc: OpenFluxError) -> JSONResponse:
        return _error_body("openflux_error", str(exc), 400)

    @app.get("/", response_class=HTMLResponse)
    async def index(request: Request) -> HTMLResponse:
        return templates.TemplateResponse("index.html", {"request": request})

    @app.get("/api/health")
    async def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.post("/api/cert/validate")
    async def cert_validate(
        fullchain: UploadFile = File(...),
        privkey: UploadFile = File(...),
        domain: str | None = Form(default=None),
    ) -> CertInfo:
        fc = await fullchain.read()
        pk = await privkey.read()
        return cert_validator.validate_cert_bytes(fc, pk, domain)

    @app.post("/api/dns/upsert")
    async def dns_upsert(body: DnsUpsertRequest) -> dict[str, str]:
        token = body.api_token or ctx.settings.cf_api_token
        if not token:
            raise ApiError("cf_auth", "Cloudflare API token is empty", 401)
        cf = ctx.cf_factory(token)
        fqdn = body.fqdn.strip().lower().rstrip(".")
        root = body.root_domain or _root_domain_from_fqdn(fqdn)
        zone_id = body.zone_id or cf.resolve_zone_id(root)
        record_id = cf.upsert_a_record(zone_id, fqdn, body.ip)
        return {"zone_id": zone_id, "record_id": record_id}

    @app.post("/api/secrets/load")
    async def secrets_load(body: SecretsIpRequest) -> Secrets:
        return ctx.store.load(body.ip)

    @app.post("/api/secrets/export")
    async def secrets_export(body: SecretsIpRequest) -> Response:
        raw = ctx.store.export(body.ip)
        return Response(
            content=raw,
            media_type="application/json",
            headers={"Content-Disposition": f'attachment; filename="{body.ip}.json"'},
        )

    @app.post("/api/secrets/import")
    async def secrets_import(
        ip: str = Form(...),
        file: UploadFile = File(...),
    ) -> Secrets:
        raw = await file.read()
        return ctx.store.import_(ip, raw)

    @app.get("/api/clients")
    async def clients_list(ip: str = Query(...)) -> list[Client]:
        if not ctx.store.exists(ip):
            return []
        return ctx.clients.list_clients(ip)

    @app.post("/api/clients")
    async def clients_add(body: ClientCreateRequest) -> Client:
        return ctx.clients.add_client(body.ip, body.label)

    @app.patch("/api/clients/{client_id}")
    async def clients_patch(client_id: str, body: ClientPatchRequest) -> Client:
        if body.label is None and body.disabled is None:
            raise ApiError("validation_error", "label or disabled is required", 422)
        client: Client | None = None
        if body.label is not None:
            client = ctx.clients.rename_client(body.ip, client_id, body.label)
        if body.disabled is True:
            client = ctx.clients.disable_client(body.ip, client_id)
        elif body.disabled is False:
            client = ctx.clients.enable_client(body.ip, client_id)
        assert client is not None
        return client

    @app.delete("/api/clients/{client_id}")
    async def clients_delete(
        client_id: str, ip: str = Query(...)
    ) -> dict[str, bool]:
        ctx.clients.remove_client(ip, client_id)
        return {"ok": True}

    @app.post("/api/clients/rotate")
    async def clients_rotate(body: ClientRotateRequest) -> list[Client]:
        return ctx.clients.rotate_all(body.ip)

    @app.post("/api/deploy")
    async def deploy_start(
        payload: str = Form(...),
        fullchain: UploadFile | None = File(default=None),
        privkey: UploadFile | None = File(default=None),
    ) -> JSONResponse:
        try:
            req = DeployRequest.model_validate_json(payload)
        except Exception as exc:
            return _error_body("validation_error", str(exc), 422)

        fc_bytes = await fullchain.read() if fullchain is not None else None
        pk_bytes = await privkey.read() if privkey is not None else None

        if req.protocols.hysteria2:
            if not req.domain:
                raise ApiError("validation_error", "hysteria2 requires domain", 422)
            if req.certificate_source == "upload" and (not fc_bytes or not pk_bytes):
                raise ApiError(
                    "validation_error",
                    "hysteria2 requires fullchain and privkey files",
                    422,
                )
            if req.certificate_source == "vps":
                if not req.vps_fullchain_path or not req.vps_privkey_path:
                    raise ApiError(
                        "validation_error",
                        "VPS certificate paths are required",
                        422,
                    )
                for cert_path in (req.vps_fullchain_path, req.vps_privkey_path):
                    if not cert_path.startswith("/") or "\x00" in cert_path:
                        raise ApiError(
                            "validation_error",
                            "VPS certificate paths must be absolute Linux paths",
                            422,
                        )

        job_id = uuid.uuid4().hex
        job = DeployJob(job_id=job_id, status="pending")
        ctx.jobs[job_id] = job
        task = asyncio.create_task(
            _run_deploy(ctx, job, req, fc_bytes, pk_bytes),
            name=f"deploy-{job_id}",
        )
        task.add_done_callback(lambda t: t.exception())
        return JSONResponse(
            status_code=202,
            content={"job_id": job_id, "status": "pending"},
        )

    @app.get("/api/deploy/stream/{job_id}")
    async def deploy_stream(job_id: str) -> EventSourceResponse:
        job = ctx.jobs.get(job_id)
        if job is None:
            raise ApiError("job_not_found", f"job {job_id} not found", 404)

        async def events() -> AsyncIterator[dict[str, str]]:
            queue = job.subscribe()
            while True:
                item = await queue.get()
                if item is None:
                    break
                yield item

        return EventSourceResponse(events())

    @app.post("/api/deploy/demo", status_code=202)
    async def deploy_demo(payload: str = Form(...)) -> dict[str, str]:
        try:
            req = DeployRequest.model_validate_json(payload)
        except ValidationError as exc:
            raise ApiError(
                "validation_error", "Invalid demo deploy payload", 422
            ) from exc

        molecule = shutil.which("molecule")
        if molecule is None:
            raise ApiError(
                "molecule_not_found", "Install Molecule to run the demo deployment", 503
            )

        job_id = uuid.uuid4().hex
        job = DeployJob(job_id=job_id)
        ctx.jobs[job_id] = job
        job.demo_task = asyncio.create_task(
            _run_demo(job, req, molecule, ctx.settings.ansible_timeout),
            name=f"demo-deploy-{job_id}",
        )
        return {"job_id": job_id, "status": "pending"}

    @app.post("/api/deploy/cancel/{job_id}")
    async def deploy_cancel(job_id: str) -> dict[str, str]:
        job = ctx.jobs.get(job_id)
        if job is None:
            raise ApiError("job_not_found", f"job {job_id} not found", 404)

        if job.demo_task is not None:
            if not job.done.is_set():
                if not job.demo_task.cancelling():
                    job.demo_task.cancel()
                with suppress(asyncio.CancelledError):
                    await job.demo_task
                if not job.done.is_set():
                    job.finish("cancelled", error="Deployment cancelled by user")
            return {"status": job.status}

        # Note: This is a simplified cancel - in production you'd want to actually
        # cancel the running Ansible process. For now, we'll just mark it as cancelled.
        job.finish("cancelled", error="Deployment cancelled by user")
        return {"status": "cancelled"}

    @app.get("/api/sub/{sub_token}", response_class=PlainTextResponse)
    async def local_sub(sub_token: str) -> str:
        for ip in ctx.store.list_ips():
            secrets = ctx.store.load(ip)
            for client in secrets.clients:
                if client.sub_token != sub_token:
                    continue
                if client.disabled:
                    raise HTTPException(status_code=404, detail="not found")
                urls = sub_builder.build_subscription_for_client(secrets, client)
                return sub_builder.encode_subscription(urls)
        raise HTTPException(status_code=404, detail="not found")

    @app.get("/api/config/{sub_token}/xray.json")
    async def local_xray_config(sub_token: str) -> Response:
        for ip in ctx.store.list_ips():
            secrets = ctx.store.load(ip)
            for client in secrets.clients:
                if client.sub_token != sub_token:
                    continue
                if client.disabled:
                    raise HTTPException(status_code=404, detail="not found")
                content = sub_builder.dump_xray_client_config(secrets, client)
                return Response(
                    content=content,
                    media_type="application/json",
                    headers={
                        "Content-Disposition": (
                            f'attachment; filename="bypass-{client.id[:8]}-xray.json"'
                        )
                    },
                )
        raise HTTPException(status_code=404, detail="not found")

    @app.get("/api/openflux/client")
    async def openflux_client(ip: str = Query(...)) -> dict[str, str | None]:
        secrets = ctx.store.load(ip)
        if not secrets.protocols.openflux:
            raise ApiError("openflux_disabled", "OpenFlux is not enabled for this VPS", 404)
        return {
            "transport": secrets.openflux.transport,
            "mode": secrets.openflux.mode,
            "codec": secrets.openflux.codec,
            "command": build_client_command(secrets),
            "encryption_key": secrets.openflux.encryption_key,
        }

    return app


def _root_domain_from_fqdn(fqdn: str) -> str:
    parts = fqdn.strip().lower().rstrip(".").split(".")
    if len(parts) < 2:
        raise CFZoneNotFound(f"cannot derive root domain from {fqdn!r}")
    return ".".join(parts[-2:])


def _ensure_protocol_secrets(secrets: Secrets, req: DeployRequest) -> None:
    secrets.protocols = req.protocols
    secrets.routing = req.routing
    if req.domain:
        secrets.domain = req.domain
    if req.protocols.vless_reality and secrets.reality is None:
        priv, pub = crypto_utils.generate_x25519_keypair()
        secrets.reality = RealityConfig(
            private_key=priv,
            public_key=pub,
            short_id=crypto_utils.generate_short_id(),
        )
    elif req.protocols.vless_reality and secrets.reality is not None:
        if (
            secrets.reality.dest == "www.microsoft.com:443"
            and secrets.reality.server_name == "www.microsoft.com"
        ):
            secrets.reality.dest = "www.apple.com:443"
            secrets.reality.server_name = "www.apple.com"
    if req.protocols.hysteria2 and secrets.hysteria2 is None:
        secrets.hysteria2 = Hysteria2Config(
            obfs_password=crypto_utils.generate_obfs_password(),
        )
    if req.protocols.openflux:
        if req.openflux is not None:
            # Keep existing session/key unless caller sent replacements.
            incoming = req.openflux
            if not incoming.encryption_key:
                incoming.encryption_key = secrets.openflux.encryption_key
            if not incoming.session_b64:
                incoming.session_b64 = secrets.openflux.session_b64
            secrets.openflux = incoming
        if not secrets.openflux.encryption_key:
            secrets.openflux.encryption_key = crypto_utils.generate_password(32)


def _apply_cert_state(secrets: Secrets, info: CertInfo | None) -> None:
    if info is None:
        return
    secrets.cert = CertState(
        not_after=info.not_after,
        issuer=info.issuer_cn,
        sha256=info.sha256,
    )


async def _run_demo(job: DeployJob, req: DeployRequest, molecule: str, timeout: int) -> None:
    job.status = "running"
    job.emit("log", "Demo deployment: running Molecule on localhost")
    try:
        with tempfile.TemporaryDirectory(prefix="vpnforge-demo-") as work_dir:
            run = await demo_deploy.run(molecule, Path(work_dir), req, timeout)
            try:
                async for line in run:
                    job.emit("log", line)
            finally:
                await run.aclose()
        if run.timed_out:
            job.finish("failed", error="Molecule timed out")
        elif run.returncode != 0:
            job.finish("failed", error=f"Molecule exited with {run.returncode}")
        else:
            job.finish("success")
    except asyncio.CancelledError:
        job.finish("cancelled", error="Deployment cancelled by user")
        raise
    except Exception:
        logger.exception("demo deployment %s crashed", job.job_id)
        job.finish("failed", error="Could not run the Molecule demo")


async def _run_deploy(
    ctx: AppContext,
    job: DeployJob,
    req: DeployRequest,
    fullchain: bytes | None,
    privkey: bytes | None,
) -> None:
    job.status = "running"
    job.emit("log", "deploy started")
    run_dir = ctx.settings.runs_dir / job.job_id
    cert_info: CertInfo | None = None
    try:
        run_dir.mkdir(parents=True, exist_ok=True)
        os.chmod(run_dir, 0o700)

        if req.protocols.hysteria2:
            assert req.domain
            if req.certificate_source == "upload":
                assert fullchain is not None and privkey is not None
                job.emit("log", "validating uploaded certificate")
                cert_info = cert_validator.validate_cert_bytes(
                    fullchain, privkey, req.domain
                )
            else:
                job.emit("log", "certificate will be validated on VPS")

            token = req.cf_api_token or ctx.settings.cf_api_token
            if token:
                job.emit("log", "upserting Cloudflare A record")
                cf = ctx.cf_factory(token)
                root = req.root_domain or _root_domain_from_fqdn(req.domain)
                secrets_preview = (
                    ctx.store.load(req.ip) if ctx.store.exists(req.ip) else None
                )
                zone_id = (
                    secrets_preview.cloudflare.zone_id if secrets_preview else None
                ) or cf.resolve_zone_id(root)
                record_id = cf.upsert_a_record(zone_id, req.domain, req.ip)
                pending_cf = (zone_id, record_id)
            else:
                job.emit("log", "skipping DNS: no Cloudflare token")
                pending_cf = None
        else:
            pending_cf = None

        if ctx.store.exists(req.ip):
            secrets = ctx.store.load(req.ip)
            job.emit("log", "loaded existing secrets")
        else:
            secrets = Secrets(ip=req.ip, domain=req.domain, protocols=req.protocols)
            job.emit("log", "created new secrets document")

        _ensure_protocol_secrets(secrets, req)
        _apply_cert_state(secrets, cert_info)
        if req.protocols.hysteria2 and req.certificate_source == "vps":
            secrets.cert = CertState()
        if pending_cf is not None:
            secrets.cloudflare.zone_id, secrets.cloudflare.record_id = pending_cf

        ctx.store.save(secrets)

        if not secrets.clients:
            job.emit("log", "adding default client")
            ctx.clients.add_client(req.ip, "default")
            secrets = ctx.store.load(req.ip)

        xray_cfg = None
        hy_cfg = None
        if secrets.protocols.vless_reality:
            xray_cfg = config_builder.build_xray_config(secrets)
        if secrets.protocols.hysteria2:
            hy_cfg = config_builder.build_hysteria_config(secrets)
        clients_json = sub_builder.build_clients_json(secrets)

        vps = VPSConnection(
            ip=req.ip,
            ssh_user=req.ssh_user,
            ssh_port=req.ssh_port,
            ssh_private_key_path=req.ssh_private_key_path,
            ssh_password=req.ssh_password,
        )
        hosts = inventory_builder.build_hosts_ini(vps)
        gv = inventory_builder.build_group_vars(
            secrets,
            cert_info,
            runtime=req.runtime,
            certificate_source=req.certificate_source,
            vps_fullchain_path=req.vps_fullchain_path,
            vps_privkey_path=req.vps_privkey_path,
            fullchain_b64=inventory_builder.encode_pem_b64(fullchain)
            if fullchain
            else None,
            privkey_b64=inventory_builder.encode_pem_b64(privkey) if privkey else None,
            ssh_password=req.ssh_password,
            xray_config=xray_cfg,
            hysteria_config=hy_cfg,
            clients_json=clients_json,
        )

        inventory_path = run_dir / "hosts.ini"
        gv_dir = run_dir / "group_vars"
        gv_dir.mkdir(parents=True, exist_ok=True)
        inventory_path.write_text(hosts, encoding="utf-8")
        gv_path = gv_dir / "all.yml"
        gv_path.write_text(inventory_builder.dump_group_vars(gv), encoding="utf-8")
        os.chmod(gv_path, 0o600)

        job.emit("log", "running ansible-playbook")
        run = await ctx.runner.run(PLAYBOOK, inventory_path)
        log_acc: list[str] = []
        async for line in run:
            log_acc.append(line)
            job.emit("log", line)

        if run.timed_out:
            job.finish("failed", error="ansible timed out")
            return
        if run.returncode != 0:
            job.finish("failed", error=f"ansible exited with {run.returncode}")
            return

        if secrets.protocols.openflux and secrets.openflux.transport == "cupsonline":
            session = parse_session_b64("\n".join(log_acc))
            if session:
                secrets.openflux.session_b64 = session
                job.emit("log", "captured OpenFlux session")

        ctx.store.save(secrets)
        job.emit("log", "secrets saved")
        job.finish("success")
    except (CertError, CFError, SecretsError, ClientError, OpenFluxError, AnsibleError) as exc:
        logger.warning("deploy %s failed: %s", job.job_id, type(exc).__name__)
        code = type(exc).__name__
        job.finish("failed", error=f"{code}: {exc}")
    except Exception as exc:
        logger.exception("deploy %s crashed", job.job_id)
        job.finish("failed", error=str(exc))
    finally:
        shutil.rmtree(run_dir, ignore_errors=True)


app = create_app()
