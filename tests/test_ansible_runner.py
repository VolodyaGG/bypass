"""Tests for vpnforge.ansible_runner."""

from __future__ import annotations

import asyncio
import os
import stat
from pathlib import Path

import pytest

from vpnforge.ansible_runner import (
    AnsibleError,
    AnsibleNotFound,
    AnsibleRunError,
    AnsibleRunner,
)

# ---------- helpers ----------


def _make_fake_bin(tmp_path: Path, script: str, name: str = "fake-ansible") -> Path:
    """Create an executable shell script that we can point AnsibleRunner at."""
    p = tmp_path / name
    p.write_text("#!/bin/sh\n" + script, encoding="utf-8")
    p.chmod(p.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
    return p


def _touch(p: Path) -> Path:
    p.write_text("dummy", encoding="utf-8")
    return p


# ---------- constructor / resolution ----------


def test_runner_rejects_missing_binary(tmp_path: Path) -> None:
    runner = AnsibleRunner(tmp_path, ansible_bin="definitely-not-a-real-bin-xyz")
    playbook = _touch(tmp_path / "play.yml")
    inventory = _touch(tmp_path / "hosts.ini")
    with pytest.raises(AnsibleNotFound):
        # _resolve_bin is called inside run()
        asyncio.run(runner.run(playbook, inventory))


async def test_run_raises_on_missing_playbook(tmp_path: Path) -> None:
    bin_path = _make_fake_bin(tmp_path, "exit 0\n")
    runner = AnsibleRunner(tmp_path, ansible_bin=str(bin_path))
    inventory = _touch(tmp_path / "hosts.ini")
    with pytest.raises(AnsibleError, match="playbook not found"):
        await runner.run(tmp_path / "no-such-playbook.yml", inventory)


async def test_run_raises_on_missing_inventory(tmp_path: Path) -> None:
    bin_path = _make_fake_bin(tmp_path, "exit 0\n")
    runner = AnsibleRunner(tmp_path, ansible_bin=str(bin_path))
    playbook = _touch(tmp_path / "play.yml")
    with pytest.raises(AnsibleError, match="inventory not found"):
        await runner.run(playbook, tmp_path / "no-hosts.ini")


async def test_run_rejects_both_extra_vars_and_file(tmp_path: Path) -> None:
    bin_path = _make_fake_bin(tmp_path, "exit 0\n")
    runner = AnsibleRunner(tmp_path, ansible_bin=str(bin_path))
    playbook = _touch(tmp_path / "play.yml")
    inventory = _touch(tmp_path / "hosts.ini")
    evf = _touch(tmp_path / "extra.yml")
    with pytest.raises(AnsibleError, match="either extra_vars or extra_vars_file"):
        await runner.run(playbook, inventory, extra_vars={"a": 1}, extra_vars_file=evf)


# ---------- happy path ----------


async def test_run_streams_lines(tmp_path: Path) -> None:
    bin_path = _make_fake_bin(
        tmp_path,
        'echo "line1"\necho "line2"\necho "line3"\nexit 0\n',
    )
    runner = AnsibleRunner(tmp_path, ansible_bin=str(bin_path))
    playbook = _touch(tmp_path / "play.yml")
    inventory = _touch(tmp_path / "hosts.ini")

    run = await runner.run(playbook, inventory)
    lines: list[str] = []
    async for line in run:
        lines.append(line)

    assert lines == ["line1", "line2", "line3"]
    assert run.returncode == 0
    assert run.timed_out is False


async def test_run_returns_nonzero_exit_code(tmp_path: Path) -> None:
    bin_path = _make_fake_bin(tmp_path, 'echo "boom"\nexit 42\n')
    runner = AnsibleRunner(tmp_path, ansible_bin=str(bin_path))
    playbook = _touch(tmp_path / "play.yml")
    inventory = _touch(tmp_path / "hosts.ini")

    run = await runner.run(playbook, inventory)
    lines = [line async for line in run]

    assert lines == ["boom"]
    assert run.returncode == 42
    assert run.timed_out is False


async def test_run_captures_stderr_into_stdout(tmp_path: Path) -> None:
    bin_path = _make_fake_bin(
        tmp_path,
        'echo "to-stdout"\necho "to-stderr" >&2\nexit 0\n',
    )
    runner = AnsibleRunner(tmp_path, ansible_bin=str(bin_path))
    playbook = _touch(tmp_path / "play.yml")
    inventory = _touch(tmp_path / "hosts.ini")

    run = await runner.run(playbook, inventory)
    lines = [line async for line in run]

    assert "to-stdout" in lines
    assert "to-stderr" in lines
    assert run.returncode == 0


async def test_run_empty_output(tmp_path: Path) -> None:
    bin_path = _make_fake_bin(tmp_path, "exit 0\n")
    runner = AnsibleRunner(tmp_path, ansible_bin=str(bin_path))
    playbook = _touch(tmp_path / "play.yml")
    inventory = _touch(tmp_path / "hosts.ini")

    run = await runner.run(playbook, inventory)
    lines = [line async for line in run]
    assert lines == []
    assert run.returncode == 0


async def test_run_strips_crlf(tmp_path: Path) -> None:
    # printf with \r\n endings
    bin_path = _make_fake_bin(
        tmp_path,
        "printf 'a\\r\\nb\\r\\n'\nexit 0\n",
    )
    runner = AnsibleRunner(tmp_path, ansible_bin=str(bin_path))
    playbook = _touch(tmp_path / "play.yml")
    inventory = _touch(tmp_path / "hosts.ini")

    run = await runner.run(playbook, inventory)
    lines = [line async for line in run]
    assert lines == ["a", "b"]


# ---------- argv / env ----------


async def test_run_passes_extra_vars_as_json(tmp_path: Path) -> None:
    # Echo argv so we can inspect it
    bin_path = _make_fake_bin(tmp_path, 'echo "$@"\nexit 0\n')
    runner = AnsibleRunner(tmp_path, ansible_bin=str(bin_path))
    playbook = _touch(tmp_path / "play.yml")
    inventory = _touch(tmp_path / "hosts.ini")

    run = await runner.run(playbook, inventory, extra_vars={"a": 1, "b": "x"})
    lines = [line async for line in run]
    joined = " ".join(lines)

    assert "--extra-vars" in joined
    assert '{"a": 1, "b": "x"}' in joined


async def test_run_passes_extra_vars_file(tmp_path: Path) -> None:
    bin_path = _make_fake_bin(tmp_path, 'echo "$@"\nexit 0\n')
    runner = AnsibleRunner(tmp_path, ansible_bin=str(bin_path))
    playbook = _touch(tmp_path / "play.yml")
    inventory = _touch(tmp_path / "hosts.ini")
    evf = _touch(tmp_path / "extra.yml")

    run = await runner.run(playbook, inventory, extra_vars_file=evf)
    lines = [line async for line in run]
    joined = " ".join(lines)

    assert f"@{evf}" in joined


async def test_run_sets_ansible_config_when_present(tmp_path: Path) -> None:
    cfg_dir = tmp_path / "ansible"
    cfg_dir.mkdir()
    (cfg_dir / "ansible.cfg").write_text("[defaults]\n", encoding="utf-8")
    bin_path = _make_fake_bin(tmp_path, 'echo "$ANSIBLE_CONFIG"\nexit 0\n')
    runner = AnsibleRunner(tmp_path, ansible_bin=str(bin_path))
    playbook = _touch(tmp_path / "play.yml")
    inventory = _touch(tmp_path / "hosts.ini")

    run = await runner.run(playbook, inventory)
    lines = [line async for line in run]
    assert lines == [str(cfg_dir / "ansible.cfg")]


async def test_run_sets_ansible_env_vars(tmp_path: Path) -> None:
    bin_path = _make_fake_bin(
        tmp_path,
        'echo "$ANSIBLE_FORCE_COLOR|$ANSIBLE_NOCOLOR|$PYTHONUNBUFFERED"\nexit 0\n',
    )
    runner = AnsibleRunner(tmp_path, ansible_bin=str(bin_path))
    playbook = _touch(tmp_path / "play.yml")
    inventory = _touch(tmp_path / "hosts.ini")

    run = await runner.run(playbook, inventory)
    lines = [line async for line in run]
    assert lines == ["0|1|1"]
    bin_path = _make_fake_bin(
        tmp_path,
        'echo "$ANSIBLE_FORCE_COLOR|$ANSIBLE_NOCOLOR|$PYTHONUNBUFFERED"\nexit 0\n',
    )
    runner = AnsibleRunner(tmp_path, ansible_bin=str(bin_path))
    playbook = _touch(tmp_path / "play.yml")
    inventory = _touch(tmp_path / "hosts.ini")

    run = await runner.run(playbook, inventory)
    lines = [line async for line in run]
    assert lines == ["0|1|1"]


async def test_run_preserves_path_env(tmp_path: Path) -> None:
    bin_path = _make_fake_bin(tmp_path, 'echo "$PATH"\nexit 0\n')
    runner = AnsibleRunner(tmp_path, ansible_bin=str(bin_path))
    playbook = _touch(tmp_path / "play.yml")
    inventory = _touch(tmp_path / "hosts.ini")

    run = await runner.run(playbook, inventory)
    lines = [line async for line in run]
    assert lines
    assert os.environ.get("PATH", "") in lines[0]


# ---------- timeout ----------


async def test_run_timeout_kills_process(tmp_path: Path) -> None:
    bin_path = _make_fake_bin(tmp_path, "sleep 30\nexit 0\n")
    runner = AnsibleRunner(tmp_path, ansible_bin=str(bin_path), timeout=0.5)
    playbook = _touch(tmp_path / "play.yml")
    inventory = _touch(tmp_path / "hosts.ini")

    run = await runner.run(playbook, inventory)
    lines = [line async for line in run]

    assert lines == []
    assert run.timed_out is True
    assert run.returncode is not None  # killed with some signal
    assert run.returncode != 0


async def test_run_timeout_after_partial_output(tmp_path: Path) -> None:
    bin_path = _make_fake_bin(
        tmp_path,
        'echo "before-timeout"\nsleep 30\nexit 0\n',
    )
    runner = AnsibleRunner(tmp_path, ansible_bin=str(bin_path), timeout=0.5)
    playbook = _touch(tmp_path / "play.yml")
    inventory = _touch(tmp_path / "hosts.ini")

    run = await runner.run(playbook, inventory)
    lines = [line async for line in run]

    assert lines == ["before-timeout"]
    assert run.timed_out is True


# ---------- early break ----------


async def test_early_break_kills_process(tmp_path: Path) -> None:
    bin_path = _make_fake_bin(
        tmp_path,
        'echo "one"\necho "two"\nsleep 30\necho "three"\n',
    )
    runner = AnsibleRunner(tmp_path, ansible_bin=str(bin_path), timeout=10.0)
    playbook = _touch(tmp_path / "play.yml")
    inventory = _touch(tmp_path / "hosts.ini")

    run = await runner.run(playbook, inventory)

    seen: list[str] = []
    async for line in run:
        seen.append(line)
        if line == "one":
            break

    await run.aclose()
    assert seen == ["one"]
    # Process killed due to early break
    assert run.timed_out is True
    assert run.returncode is not None


# ---------- single iteration ----------


async def test_run_cannot_be_iterated_twice(tmp_path: Path) -> None:
    bin_path = _make_fake_bin(tmp_path, 'echo "x"\nexit 0\n')
    runner = AnsibleRunner(tmp_path, ansible_bin=str(bin_path))
    playbook = _touch(tmp_path / "play.yml")
    inventory = _touch(tmp_path / "hosts.ini")

    run = await runner.run(playbook, inventory)
    _ = [line async for line in run]

    with pytest.raises(AnsibleError, match="only be iterated once"):
        async for _ in run:
            pass


# ---------- tail ----------


async def test_tail_captures_last_lines(tmp_path: Path) -> None:
    script = "".join(f'echo "line{i}"\n' for i in range(30))
    script += "exit 1\n"
    bin_path = _make_fake_bin(tmp_path, script)
    runner = AnsibleRunner(tmp_path, ansible_bin=str(bin_path))
    playbook = _touch(tmp_path / "play.yml")
    inventory = _touch(tmp_path / "hosts.ini")

    run = await runner.run(playbook, inventory)
    _ = [line async for line in run]

    assert run.returncode == 1
    tail_lines = run.tail.split("\n")
    assert len(tail_lines) == 20
    assert tail_lines[0] == "line10"
    assert tail_lines[-1] == "line29"


async def test_tail_empty_on_no_output(tmp_path: Path) -> None:
    bin_path = _make_fake_bin(tmp_path, "exit 0\n")
    runner = AnsibleRunner(tmp_path, ansible_bin=str(bin_path))
    playbook = _touch(tmp_path / "play.yml")
    inventory = _touch(tmp_path / "hosts.ini")

    run = await runner.run(playbook, inventory)
    _ = [line async for line in run]
    assert run.tail == ""


# ---------- cwd ----------


async def test_run_uses_project_root_as_cwd(tmp_path: Path) -> None:
    project_root = tmp_path / "proj"
    project_root.mkdir()
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    bin_path = _make_fake_bin(bin_dir, "pwd\nexit 0\n")

    runner = AnsibleRunner(project_root, ansible_bin=str(bin_path))
    playbook = _touch(project_root / "play.yml")
    inventory = _touch(project_root / "hosts.ini")

    run = await runner.run(playbook, inventory)
    lines = [line async for line in run]

    assert lines[0] == str(project_root)


# ---------- exceptions ----------


def test_ansible_run_error_carries_code() -> None:
    e = AnsibleRunError(2, tail="oops")
    assert e.returncode == 2
    assert e.tail == "oops"
    assert "2" in str(e)
