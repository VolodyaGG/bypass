"""Async wrapper around `ansible-playbook`.

Streams stdout+stderr line by line, enforces a timeout (kill on expiry),
and exposes the exit code after iteration.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import shutil
from collections.abc import AsyncIterator
from contextlib import suppress
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

DEFAULT_TIMEOUT = 30 * 60  # 30 minutes per TZ


class AnsibleError(Exception):
    """Base class for ansible_runner errors."""


class AnsibleNotFound(AnsibleError):
    """The ansible-playbook binary is not on PATH."""


class AnsibleRunError(AnsibleError):
    """ansible-playbook exited with a non-zero code."""

    def __init__(self, returncode: int, tail: str = "") -> None:
        self.returncode = returncode
        self.tail = tail
        super().__init__(f"ansible-playbook exited with code {returncode}")


class AnsibleRun:
    """Async iterable over ansible-playbook output lines.

    Usage:
        run = runner.run(playbook=..., inventory=...)
        async for line in run:
            print(line)
        if run.returncode != 0:
            ...
    """

    def __init__(
        self,
        proc: asyncio.subprocess.Process,
        timeout: float,
    ) -> None:
        self._proc = proc
        self._timeout = max(timeout, 1.0)
        self.returncode: int | None = None
        self.timed_out: bool = False
        self._finished: bool = False
        # Ring buffer of last N lines for error messages.
        self._tail: list[str] = []
        self._tail_max = 20

    def __aiter__(self) -> AsyncIterator[str]:
        return self._iterate()

    async def _iterate(self) -> AsyncIterator[str]:
        if self._finished:
            raise AnsibleError("AnsibleRun can only be iterated once")
        self._finished = True

        assert self._proc.stdout is not None

        loop = asyncio.get_event_loop()
        deadline = loop.time() + self._timeout

        try:
            while True:
                remaining = deadline - loop.time()
                if remaining <= 0:
                    await self._kill_and_mark_timeout()
                    return

                try:
                    raw = await asyncio.wait_for(
                        self._proc.stdout.readline(), timeout=remaining
                    )
                except TimeoutError:
                    await self._kill_and_mark_timeout()
                    return

                if not raw:
                    # EOF — process closed stdout
                    break

                line = raw.decode("utf-8", errors="replace").rstrip("\r\n")
                self._tail.append(line)
                if len(self._tail) > self._tail_max:
                    self._tail.pop(0)
                yield line

            # Wait for exit (should be immediate after EOF, but be safe).
            try:
                await asyncio.wait_for(self._proc.wait(), timeout=5.0)
            except TimeoutError:
                await self._kill_and_mark_timeout()
                return

            self.returncode = self._proc.returncode
        finally:
            if self.returncode is None and not self.timed_out:
                # Consumer broke out of the loop early.
                await self._kill_and_mark_timeout()

    async def _kill_and_mark_timeout(self) -> None:
        if self._proc.returncode is None:
            with suppress(ProcessLookupError):
                self._proc.kill()
            await self._proc.wait()
        self.returncode = self._proc.returncode
        self.timed_out = True
        logger.warning("ansible-playbook killed (timeout or early exit)")

    async def aclose(self) -> None:
        """Stop the underlying process when a consumer exits early."""
        if self.returncode is None:
            await self._kill_and_mark_timeout()

    @property
    def tail(self) -> str:
        """Last N lines, for error messages."""
        return "\n".join(self._tail)


class AnsibleRunner:
    """Spawns `ansible-playbook` with a fixed cwd and sanitized env."""

    def __init__(
        self,
        project_root: Path,
        ansible_bin: str = "ansible-playbook",
        timeout: float = DEFAULT_TIMEOUT,
    ) -> None:
        self._root = Path(project_root)
        self._bin = ansible_bin
        self._timeout = timeout

    def _resolve_bin(self) -> str:
        path = shutil.which(self._bin)
        if path is None:
            raise AnsibleNotFound(f"{self._bin!r} not found on PATH")
        return path

    def _build_env(self) -> dict[str, str]:
        env = dict(os.environ)
        env["ANSIBLE_FORCE_COLOR"] = "0"
        env["ANSIBLE_NOCOLOR"] = "1"
        env["PYTHONUNBUFFERED"] = "1"
        cfg = self._root / "ansible" / "ansible.cfg"
        if cfg.is_file():
            env["ANSIBLE_CONFIG"] = str(cfg)
        return env

    def _build_argv(
        self,
        playbook: Path,
        inventory: Path,
        extra_vars: dict[str, Any] | None,
        extra_vars_file: Path | None,
    ) -> list[str]:
        if extra_vars is not None and extra_vars_file is not None:
            raise AnsibleError(
                "pass either extra_vars or extra_vars_file, not both"
            )

        argv = [
            self._resolve_bin(),
            "-i",
            str(inventory),
            str(playbook),
        ]
        if extra_vars_file is not None:
            argv += ["--extra-vars", f"@{extra_vars_file}"]
        elif extra_vars is not None:
            argv += ["--extra-vars", json.dumps(extra_vars)]
        return argv

    async def run(
        self,
        playbook: Path,
        inventory: Path,
        extra_vars: dict[str, Any] | None = None,
        extra_vars_file: Path | None = None,
    ) -> AnsibleRun:
        """Spawn the process and return an AnsibleRun (async iterable)."""
        playbook = Path(playbook)
        inventory = Path(inventory)

        if not playbook.is_file():
            raise AnsibleError(f"playbook not found: {playbook}")
        if not inventory.is_file():
            raise AnsibleError(f"inventory not found: {inventory}")

        argv = self._build_argv(playbook, inventory, extra_vars, extra_vars_file)
        env = self._build_env()

        # Never log argv verbatim — extra_vars may contain secrets.
        logger.info("Running ansible-playbook %s with inventory %s", playbook.name, inventory.name)

        proc = await asyncio.create_subprocess_exec(
            *argv,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            cwd=str(self._root),
            env=env,
        )

        return AnsibleRun(proc, timeout=self._timeout)
