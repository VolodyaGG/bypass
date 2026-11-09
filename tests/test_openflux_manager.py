"""Tests for vpnforge.openflux_manager (OpenFlux exit-node)."""

from __future__ import annotations

import base64
import stat
from pathlib import Path

import pytest
from freezegun import freeze_time

from vpnforge.ansible_runner import AnsibleRunner
from vpnforge.models import (
    OpenFluxConfig,
    ProtocolFlags,
    Secrets,
)
from vpnforge.openflux_manager import (
    MARKER,
    OPENFLUX_BIN,
    OPENFLUX_KEY_PATH,
    OpenFluxDeployFailed,
    OpenFluxError,
    build_client_argv,
    build_exit_node_argv,
    fetch_session_with_retry,
    parse_session_b64,
    persist_session,
    run_openflux_deploy,
)
from vpnforge.secrets_store import SecretsStore

# ---------- helpers ----------


def _valid_b64(payload: bytes = b"hello-world-session-data") -> str:
    return base64.b64encode(payload).decode("ascii")


def _realistic_cups_logs(session_b64: str) -> str:
    """Logs shaped exactly like upstream README output."""
    return (
        "2026-09-14T12:00:00Z openflux exit-node starting\n"
        "2026-09-14T12:00:01Z transport=cupsonline rooms=4\n"
        "2026-09-14T12:00:02Z created rooms\n"
        "=== COPY THIS TO CLIENT ===\n"
        f"{session_b64}\n"
        "===========================\n"
        "2026-09-14T12:00:03Z ready\n"
    )


def _make_fake_bin(tmp_path: Path, script: str, name: str = "fake-ansible") -> Path:
    p = tmp_path / name
    p.write_text("#!/bin/sh\n" + script, encoding="utf-8")
    p.chmod(p.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
    return p


def _touch(p: Path) -> Path:
    p.write_text("x", encoding="utf-8")
    return p


def _secrets_with_openflux(**overrides) -> Secrets:
    cfg = OpenFluxConfig(**overrides)
    return Secrets(
        ip="1.2.3.4",
        protocols=ProtocolFlags(openflux=True),
        openflux=cfg,
    )


# ---------- parse_session_b64: realistic ----------


def test_parse_exact_readme_format() -> None:
    b64 = _valid_b64()
    text = (
        "=== COPY THIS TO CLIENT ===\n"
        f"{b64}\n"
        "===========================\n"
    )
    assert parse_session_b64(text) == b64


def test_parse_with_surrounding_logs() -> None:
    b64 = _valid_b64()
    assert parse_session_b64(_realistic_cups_logs(b64)) == b64


def test_parse_case_insensitive_marker() -> None:
    b64 = _valid_b64()
    assert parse_session_b64(f"copy this to client\n{b64}\n") == b64


def test_parse_same_line_colon() -> None:
    b64 = _valid_b64()
    assert parse_session_b64(f"{MARKER}: {b64}\n") == b64


def test_parse_strips_quotes_on_same_line() -> None:
    b64 = _valid_b64()
    assert parse_session_b64(f"{MARKER}: '{b64}'\n") == b64


def test_parse_returns_first_match() -> None:
    b64a = _valid_b64(b"first-session-payload!!")
    b64b = _valid_b64(b"second-session-payload!")
    text = f"=== {MARKER} ===\n{b64a}\n===\n=== {MARKER} ===\n{b64b}\n"
    assert parse_session_b64(text) == b64a


def test_parse_marker_is_substring() -> None:
    b64 = _valid_b64()
    text = f"2026-09-14T12:00:02Z [info] {MARKER}: {b64}\n"
    assert parse_session_b64(text) == b64


# ---------- parse_session_b64: negatives ----------


def test_parse_no_marker() -> None:
    assert parse_session_b64("nothing here\nrandom\n") is None


def test_parse_empty() -> None:
    assert parse_session_b64("") is None


def test_parse_marker_without_payload() -> None:
    assert parse_session_b64(f"=== {MARKER} ===\n===\n") is None


def test_parse_marker_next_line_garbage() -> None:
    assert parse_session_b64(f"{MARKER}\nnot base64!!!\n") is None


def test_parse_rejects_short_b64() -> None:
    short = base64.b64encode(b"tiny").decode("ascii")
    assert parse_session_b64(f"{MARKER}\n{short}\n") is None


def test_parse_rejects_non_multiple_of_4() -> None:
    assert parse_session_b64(f"{MARKER}\nAAAAABBB\n") is None


def test_parse_rejects_urlsafe_b64() -> None:
    urlsafe = base64.urlsafe_b64encode(b"x" * 40).decode("ascii")
    assert parse_session_b64(f"{MARKER}\n{urlsafe}\n") is None


def test_parse_skips_invalid_first_marker() -> None:
    good = _valid_b64()
    text = f"{MARKER}\nnot-base64\n{MARKER}\n{good}\n"
    assert parse_session_b64(text) == good


# ---------- build_exit_node_argv ----------


def test_argv_cupsonline_l4_default() -> None:
    s = _secrets_with_openflux(transport="cupsonline", mode="proxy")
    argv = build_exit_node_argv(s)
    assert argv == [
        OPENFLUX_BIN,
        "--role",
        "exit",
        "--transport",
        "cupsonline",
        "--mode",
        "l4",
        "--codec",
        "batched",
    ]


def test_argv_never_contains_socks5() -> None:
    """--socks5 is a CLIENT flag; must not leak into exit-node argv."""
    s = _secrets_with_openflux()
    argv = build_exit_node_argv(s)
    assert "--socks5" not in argv


def test_argv_yandex_requires_url() -> None:
    s = _secrets_with_openflux(transport="yandex", mode="proxy")
    with pytest.raises(OpenFluxError, match="document URL"):
        build_exit_node_argv(s)


def test_argv_yandex_with_url() -> None:
    s = _secrets_with_openflux(
        transport="yandex",
        mode="proxy",
        yandex_url="https://docs.yandex.ru/x",
    )
    argv = build_exit_node_argv(s)
    assert "--url" in argv
    assert "https://docs.yandex.ru/x" in argv


def test_argv_oneme_requires_token_and_uid() -> None:
    s = _secrets_with_openflux(transport="oneme", mode="proxy")
    with pytest.raises(OpenFluxError, match="max_token"):
        build_exit_node_argv(s)


def test_argv_oneme_with_creds() -> None:
    s = _secrets_with_openflux(
        transport="oneme",
        mode="proxy",
        max_token="tok",
        max_uid="uid-1",
    )
    argv = build_exit_node_argv(s)
    assert "--maxToken" in argv
    assert "tok" in argv
    assert "--maxUid" in argv
    assert "uid-1" in argv


def test_argv_l3_can_auto_detect_local_ip() -> None:
    s = _secrets_with_openflux(mode="raw")
    argv = build_exit_node_argv(s)
    assert "l3" in argv
    assert "--local-ip" not in argv


def test_argv_l3_with_local_ip() -> None:
    s = _secrets_with_openflux(mode="raw", local_ip="203.0.113.10")
    argv = build_exit_node_argv(s)
    assert "--mode" in argv
    assert "l3" in argv
    assert "--local-ip" in argv
    assert "203.0.113.10" in argv


def test_argv_with_encryption_key_uses_fixed_path() -> None:
    s = _secrets_with_openflux(encryption_key="some-base64-key")
    argv = build_exit_node_argv(s)
    assert "--encryption-key-file" in argv
    assert OPENFLUX_KEY_PATH in argv


def test_argv_without_encryption_key() -> None:
    s = _secrets_with_openflux()
    argv = build_exit_node_argv(s)
    assert "--encryption-key-file" not in argv


def test_argv_debug_flag() -> None:
    s = _secrets_with_openflux(debug=True)
    argv = build_exit_node_argv(s)
    assert "--debug" in argv


def test_argv_no_debug_by_default() -> None:
    s = _secrets_with_openflux()
    argv = build_exit_node_argv(s)
    assert "--debug" not in argv


def test_argv_cupsonline_has_no_url() -> None:
    """cupsonline exit-node must NOT receive --url."""
    s = _secrets_with_openflux(transport="cupsonline", yandex_url="https://x")
    argv = build_exit_node_argv(s)
    assert "--url" not in argv


@pytest.mark.parametrize("transport", ["yandex", "vyandex", "mailru"])
def test_document_transports_use_url(transport: str) -> None:
    s = _secrets_with_openflux(transport=transport, yandex_url="https://docs.example/x")
    argv = build_exit_node_argv(s)
    assert argv[argv.index("--url") + 1] == "https://docs.example/x"


def test_argv_legacy_codec() -> None:
    s = _secrets_with_openflux(codec="legacy")
    argv = build_exit_node_argv(s)
    assert argv[argv.index("--codec") + 1] == "legacy"


def test_client_argv_cupsonline_uses_session_and_matching_codec() -> None:
    session = _valid_b64()
    secrets = _secrets_with_openflux(
        transport="cupsonline",
        codec="batched",
        session_b64=session,
        encryption_key="secret",
    )
    argv = build_client_argv(secrets)
    assert argv[:4] == ["openflux", "--role", "client", "--inbound"]
    assert argv[argv.index("--url") + 1] == session
    assert argv[argv.index("--codec") + 1] == "batched"
    assert "openflux.key" in argv


def test_client_argv_cupsonline_requires_deployed_session() -> None:
    secrets = _secrets_with_openflux(transport="cupsonline")
    with pytest.raises(OpenFluxError, match="deploy the exit node"):
        build_client_argv(secrets)


# ---------- fetch_session_with_retry ----------


async def test_fetch_succeeds_first_try() -> None:
    b64 = _valid_b64()

    async def fetch() -> str:
        return _realistic_cups_logs(b64)

    async def no_sleep(_: float) -> None:
        return None

    assert await fetch_session_with_retry(fetch, sleep=no_sleep) == b64


async def test_fetch_retries_then_succeeds() -> None:
    b64 = _valid_b64()
    calls = {"n": 0}

    async def fetch() -> str:
        calls["n"] += 1
        if calls["n"] < 3:
            return "no marker yet\n"
        return _realistic_cups_logs(b64)

    async def no_sleep(_: float) -> None:
        return None

    assert await fetch_session_with_retry(fetch, sleep=no_sleep) == b64
    assert calls["n"] == 3


async def test_fetch_gives_up_after_retries() -> None:
    calls = {"n": 0}

    async def fetch() -> str:
        calls["n"] += 1
        return "no marker ever\n"

    async def no_sleep(_: float) -> None:
        return None

    assert await fetch_session_with_retry(fetch, retries=3, sleep=no_sleep) is None
    assert calls["n"] == 3


async def test_fetch_retries_on_exception() -> None:
    b64 = _valid_b64()
    calls = {"n": 0}

    async def fetch() -> str:
        calls["n"] += 1
        if calls["n"] == 1:
            raise RuntimeError("transient")
        return _realistic_cups_logs(b64)

    async def no_sleep(_: float) -> None:
        return None

    assert await fetch_session_with_retry(fetch, sleep=no_sleep) == b64
    assert calls["n"] == 2


async def test_fetch_all_attempts_fail_with_exception() -> None:
    calls = {"n": 0}

    async def fetch() -> str:
        calls["n"] += 1
        raise RuntimeError("always fails")

    async def no_sleep(_: float) -> None:
        return None

    assert await fetch_session_with_retry(fetch, retries=4, sleep=no_sleep) is None
    assert calls["n"] == 4


async def test_fetch_sleep_called_between_attempts() -> None:
    sleeps: list[float] = []

    async def fetch() -> str:
        return "nothing\n"

    async def record_sleep(s: float) -> None:
        sleeps.append(s)

    await fetch_session_with_retry(fetch, retries=3, delay=1.5, sleep=record_sleep)
    assert sleeps == [1.5, 1.5]


async def test_fetch_none_does_not_crash() -> None:
    async def fetch() -> str | None:
        return None  # type: ignore[return-value]

    async def no_sleep(_: float) -> None:
        return None

    assert await fetch_session_with_retry(fetch, retries=2, sleep=no_sleep) is None


# ---------- persist_session ----------


def test_persist_session_writes(tmp_secrets_dir: Path) -> None:
    store = SecretsStore(tmp_secrets_dir)
    store.save(_secrets_with_openflux())

    b64 = _valid_b64()
    persist_session(store, "1.2.3.4", b64)

    assert store.load("1.2.3.4").openflux.session_b64 == b64


def test_persist_session_overwrites(tmp_secrets_dir: Path) -> None:
    store = SecretsStore(tmp_secrets_dir)
    store.save(_secrets_with_openflux(session_b64="OLD"))

    new = _valid_b64(b"new-session-data-here!!")
    persist_session(store, "1.2.3.4", new)

    assert store.load("1.2.3.4").openflux.session_b64 == new


def test_persist_session_noop_when_same(tmp_secrets_dir: Path) -> None:
    store = SecretsStore(tmp_secrets_dir)
    b64 = _valid_b64()
    with freeze_time("2026-09-14T12:00:00Z"):
        store.save(_secrets_with_openflux(session_b64=b64))
        before = store.load("1.2.3.4").updated_at

    with freeze_time("2026-09-14T12:05:00Z"):
        persist_session(store, "1.2.3.4", b64)
        after = store.load("1.2.3.4").updated_at

    assert before == after


# ---------- OpenFluxDeploy ----------


async def test_deploy_cupsonline_collects_session(tmp_path: Path) -> None:
    b64 = _valid_b64()
    script = (
        'echo "starting openflux"\n'
        f'echo "=== {MARKER} ==="\n'
        f'echo "{b64}"\n'
        'echo "==="\n'
        'echo "done"\n'
        "exit 0\n"
    )
    bin_path = _make_fake_bin(tmp_path, script)
    runner = AnsibleRunner(tmp_path, ansible_bin=str(bin_path))
    playbook = _touch(tmp_path / "play.yml")
    inventory = _touch(tmp_path / "hosts.ini")
    secrets = _secrets_with_openflux(transport="cupsonline")

    deploy = await run_openflux_deploy(runner, playbook, inventory, secrets)
    lines = [line async for line in deploy]

    assert "starting openflux" in lines
    assert deploy.session_b64 == b64
    assert deploy.returncode == 0


async def test_deploy_yandex_skips_session_parse(tmp_path: Path) -> None:
    """Even if logs accidentally contain the marker, yandex must not parse."""
    b64 = _valid_b64()
    script = (
        f'echo "=== {MARKER} ==="\n'
        f'echo "{b64}"\n'
        'echo "==="\n'
        "exit 0\n"
    )
    bin_path = _make_fake_bin(tmp_path, script)
    runner = AnsibleRunner(tmp_path, ansible_bin=str(bin_path))
    playbook = _touch(tmp_path / "play.yml")
    inventory = _touch(tmp_path / "hosts.ini")
    secrets = _secrets_with_openflux(
        transport="yandex", yandex_url="https://docs.yandex.ru/x"
    )

    deploy = await run_openflux_deploy(runner, playbook, inventory, secrets)
    _ = [line async for line in deploy]

    assert deploy.session_b64 is None


async def test_deploy_oneme_skips_session_parse(tmp_path: Path) -> None:
    b64 = _valid_b64()
    script = (
        f'echo "=== {MARKER} ==="\n'
        f'echo "{b64}"\n'
        'echo "==="\n'
        "exit 0\n"
    )
    bin_path = _make_fake_bin(tmp_path, script)
    runner = AnsibleRunner(tmp_path, ansible_bin=str(bin_path))
    playbook = _touch(tmp_path / "play.yml")
    inventory = _touch(tmp_path / "hosts.ini")
    secrets = _secrets_with_openflux(
        transport="oneme", max_token="t", max_uid="u"
    )

    deploy = await run_openflux_deploy(runner, playbook, inventory, secrets)
    _ = [line async for line in deploy]

    assert deploy.session_b64 is None


async def test_deploy_no_session_returns_none(tmp_path: Path) -> None:
    bin_path = _make_fake_bin(tmp_path, 'echo "nothing useful"\nexit 0\n')
    runner = AnsibleRunner(tmp_path, ansible_bin=str(bin_path))
    playbook = _touch(tmp_path / "play.yml")
    inventory = _touch(tmp_path / "hosts.ini")
    secrets = _secrets_with_openflux(transport="cupsonline")

    deploy = await run_openflux_deploy(runner, playbook, inventory, secrets)
    _ = [line async for line in deploy]

    assert deploy.session_b64 is None
    assert deploy.returncode == 0


async def test_deploy_can_be_iterated_once(tmp_path: Path) -> None:
    bin_path = _make_fake_bin(tmp_path, 'echo "x"\nexit 0\n')
    runner = AnsibleRunner(tmp_path, ansible_bin=str(bin_path))
    playbook = _touch(tmp_path / "play.yml")
    inventory = _touch(tmp_path / "hosts.ini")
    secrets = _secrets_with_openflux()

    deploy = await run_openflux_deploy(runner, playbook, inventory, secrets)
    _ = [line async for line in deploy]

    with pytest.raises(OpenFluxError, match="once"):
        async for _ in deploy:
            pass


async def test_deploy_raise_if_failed_on_nonzero(tmp_path: Path) -> None:
    bin_path = _make_fake_bin(tmp_path, 'echo "boom"\nexit 7\n')
    runner = AnsibleRunner(tmp_path, ansible_bin=str(bin_path))
    playbook = _touch(tmp_path / "play.yml")
    inventory = _touch(tmp_path / "hosts.ini")
    secrets = _secrets_with_openflux()

    deploy = await run_openflux_deploy(runner, playbook, inventory, secrets)
    _ = [line async for line in deploy]

    with pytest.raises(OpenFluxDeployFailed) as ei:
        deploy.raise_if_failed()
    assert ei.value.returncode == 7


async def test_deploy_raise_if_failed_on_timeout(tmp_path: Path) -> None:
    bin_path = _make_fake_bin(tmp_path, "sleep 30\nexit 0\n")
    runner = AnsibleRunner(tmp_path, ansible_bin=str(bin_path), timeout=0.5)
    playbook = _touch(tmp_path / "play.yml")
    inventory = _touch(tmp_path / "hosts.ini")
    secrets = _secrets_with_openflux()

    deploy = await run_openflux_deploy(runner, playbook, inventory, secrets)
    _ = [line async for line in deploy]

    with pytest.raises(OpenFluxDeployFailed):
        deploy.raise_if_failed()


async def test_deploy_raise_if_failed_before_iteration(tmp_path: Path) -> None:
    bin_path = _make_fake_bin(tmp_path, "exit 0\n")
    runner = AnsibleRunner(tmp_path, ansible_bin=str(bin_path))
    playbook = _touch(tmp_path / "play.yml")
    inventory = _touch(tmp_path / "hosts.ini")
    secrets = _secrets_with_openflux()

    deploy = await run_openflux_deploy(runner, playbook, inventory, secrets)
    with pytest.raises(OpenFluxError, match="not finished"):
        deploy.raise_if_failed()


async def test_deploy_raise_if_failed_noop_on_success(tmp_path: Path) -> None:
    bin_path = _make_fake_bin(tmp_path, "exit 0\n")
    runner = AnsibleRunner(tmp_path, ansible_bin=str(bin_path))
    playbook = _touch(tmp_path / "play.yml")
    inventory = _touch(tmp_path / "hosts.ini")
    secrets = _secrets_with_openflux()

    deploy = await run_openflux_deploy(runner, playbook, inventory, secrets)
    _ = [line async for line in deploy]
    deploy.raise_if_failed()  # must not raise


async def test_deploy_tail_property(tmp_path: Path) -> None:
    script = "".join(f'echo "l{i}"\n' for i in range(5)) + "exit 0\n"
    bin_path = _make_fake_bin(tmp_path, script)
    runner = AnsibleRunner(tmp_path, ansible_bin=str(bin_path))
    playbook = _touch(tmp_path / "play.yml")
    inventory = _touch(tmp_path / "hosts.ini")
    secrets = _secrets_with_openflux()

    deploy = await run_openflux_deploy(runner, playbook, inventory, secrets)
    _ = [line async for line in deploy]

    assert "l4" in deploy.tail
