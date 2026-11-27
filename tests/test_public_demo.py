"""Regressions for the public application's access boundary."""

from pathlib import Path

import pytest
from httpx import ASGITransport, AsyncClient

from vpnforge.config import Settings
from vpnforge.main import create_app


async def test_public_demo_login_and_private_routes(tmp_path: Path) -> None:
    settings = Settings(
        data_dir=tmp_path,
        public_demo=True,
        public_host="demo.example.test",
        demo_password="public-test-password",
    )
    app = create_app(settings=settings)
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="https://demo.example.test"
    ) as client:
        assert (await client.get("/api/health")).status_code == 200
        response = await client.post(
            "/login", data={"profile": "reviewer", "password": "public-test-password"}
        )
        assert response.status_code == 303
        assert "Secure" in response.headers["set-cookie"]
        panel = await client.get("/")
        assert 'data-deploy-mode="real"' not in panel.text
        for path in ["/api/secrets/load", "/api/deploy", "/api/sub/token", "/api/clients"]:
            assert (await client.get(path)).status_code == 403
        assert (await client.get("/api/health", headers={"Host": "wrong.test"})).status_code == 400
        for _ in range(9):
            await client.post("/login", data={"profile": "x"})
        assert (await client.post("/login", data={})).status_code == 429
    # Same persistent volume keeps the account and its sessions across process restarts.
    restarted = create_app(settings=settings)
    async with AsyncClient(
        transport=ASGITransport(app=restarted),
        base_url="https://demo.example.test",
        cookies=client.cookies,
    ) as client:
        assert (await client.get("/")).status_code == 200


def test_public_demo_requires_explicit_configuration(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="Public demo requires"):
        create_app(settings=Settings(data_dir=tmp_path, public_demo=True))
