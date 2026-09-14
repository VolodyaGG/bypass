"""OpenFlux exit-node manager.

OpenFlux (https://github.com/p1neappleXpress/OpenFlux) is a TCP tunnel
with pluggable transports. The exit-node binary is `universal-bypass-tool`
and is invoked as::

    universal-bypass-tool --exit-node --transport <t> --mode <m> [...]

Session extraction is ONLY meaningful for the ``cupsonline`` transport:
that transport creates a set of Centrifugo rooms at startup and prints a
base64 room list to stdout/logs::

    === COPY THIS TO CLIENT ===
    eyJyb29tcyI6WyI0YTFh...base64...
    ===========================

That blob is what the user pastes into the client's ``--url``. Every
exit-node restart produces a NEW room list — the old one becomes invalid.

For ``yandex`` the client uses the same Yandex Docs URL as the exit node
(``yandex_url``), and for ``oneme`` the client uses ``max_token`` /
``max_uid``. Neither of those prints a session blob. We therefore do
NOT attempt to parse a session for them.
"""

from __future__ import annotations

import asyncio
import base64
import binascii
import logging
import re
from pathlib import Path
from typing import Any, AsyncIterator, Callable

from vpnforge.ansible_runner import AnsibleRun, AnsibleRunner
from vpnforge.models import Secrets
from vpnforge.secrets_store import SecretsStore

logger = logging.getLogger(__name__)

# Marker emitted verbatim by the cupsonline exit node (upstream README).
MARKER = "COPY THIS TO CLIENT"

DEFAULT_RETRIES = 5
DEFAULT_RETRY_DELAY = 3.0
MIN_SESSION_BYTES = 16

# Lines that are pure decoration around the marker: "=== ... ==="
_DECOR_LINE_RE = re.compile(r"^=+\s*$")

# Standard base64 (not urlsafe): A-Za-z0-9 + / and optional = padding.
_B64_RE = re.compile(r"^[A-Za-z0-9+/]+={0,2}$")

# Paths used by the systemd unit / Ansible template.
OPENFLUX_BIN = "/usr/local/bin/universal-bypass-tool"
OPENFLUX_KEY_PATH = "/etc/vpnforge/openflux.key"


class OpenFluxError(Exception):
    """Base class for openflux_manager errors."""


class OpenFluxDeployFailed(OpenFluxError):
    """The deploy playbook exited non-zero."""

    def __init__(self, returncode: int, tail: str = "") -> None:
        self.returncode = returncode
        self.tail = tail
        super().__init__(f"openflux deploy failed with code {returncode}")


# ---------- argv builder ----------


def build_exit_node_argv(secrets: Secrets) -> list[str]:
    """Build argv for the exit-node process.

    Pure function; mirrors what the Ansible template renders. Kept here
    so it can be unit-tested and reused (e.g. for a local dry-run).

    Notes:
      * `--socks5` is a CLIENT flag; never passed to the exit node.
      * `--url` is required for yandex and passed as-is.
      * For cupsonline no `--url` is needed — the exit node prints the
        room list itself.
      * For raw mode `--local-ip` is required.
    """
    o = secrets.openflux

    argv: list[str] = [
        OPENFLUX_BIN,
        "--exit-node",
        "--transport",
        o.transport,
        "--mode",
        o.mode,
    ]

    if o.mode == "raw":
        if not o.local_ip:
            raise OpenFluxError("raw mode requires local_ip")
        argv += ["--local-ip", o.local_ip]

    if o.transport == "yandex":
        if not o.yandex_url:
            raise OpenFluxError("yandex transport requires yandex_url")
        argv += ["--url", o.yandex_url]

    if o.transport == "oneme":
        if not o.max_token or not o.max_uid:
            raise OpenFluxError("oneme transport requires max_token and max_uid")
        argv += ["--maxToken", o.max_token, "--maxUid", o.max_uid]

    if o.encryption_key:
        argv += ["--encryption-key-file", OPENFLUX_KEY_PATH]

    if o.debug:
        argv.append("--debug")

    return argv


# ---------- parsing ----------


def parse_session_b64(log_output: str) -> str | None:
    """Extract the base64 room list from cupsonline exit-node logs.

    Expected shape (verbatim from upstream README)::

        === COPY THIS TO CLIENT ===
        eyJyb29tcyI6WyI0YTFh...base64...
        ===========================

    Also tolerates a same-line payload (``COPY THIS TO CLIENT: <b64>``)
    for robustness against minor format drift.
    """
    if not log_output:
        return None

    lines = log_output.splitlines()

    for i, line in enumerate(lines):
        if MARKER.lower() not in line.lower():
            continue

        # Same-line payload, if any.
        same_line = _extract_same_line(line)
        if same_line and _is_valid_b64(same_line):
            return same_line

        # Next non-empty, non-decoration line.
        for j in range(i + 1, len(lines)):
            candidate = lines[j].strip()
            if not candidate:
                continue
            if _DECOR_LINE_RE.match(candidate):
                continue
            if _is_valid_b64(candidate):
                return candidate
            # First real content line was not base64 — bail on this marker.
            break

    return None


def _extract_same_line(line: str) -> str | None:
    """Return a same-line payload after MARKER, if any."""
    lower = line.lower()
    idx = lower.find(MARKER.lower())
    if idx < 0:
        return None
    rest = line[idx + len(MARKER):]
    # Strip decorative '=' on both sides, then separators.
    rest = rest.strip().strip("=").strip()
    rest = rest.lstrip(" :=\t").strip()
    if len(rest) >= 2 and rest[0] == rest[-1] and rest[0] in ("'", '"'):
        rest = rest[1:-1]
    return rest or None


def _is_valid_b64(s: str) -> bool:
    """Strict-ish check: standard alphabet, proper padding, non-trivial length."""
    s = s.strip()
    if len(s) < 24:
        return False
    if len(s) % 4 != 0:
        return False
    if not _B64_RE.match(s):
        return False
    try:
        raw = base64.b64decode(s, validate=True)
    except (binascii.Error, ValueError):
        return False
    return len(raw) >= MIN_SESSION_BYTES


# ---------- deploy ----------


class OpenFluxDeploy:
    """Async iterable over deploy output; exposes session_b64 after iteration.

    Session is parsed only when transport is ``cupsonline`` — for other
    transports the exit node does not print a session blob.
    """

    def __init__(self, run: AnsibleRun, transport: str) -> None:
        self._run = run
        self._transport = transport
        self.session_b64: str | None = None
        self.returncode: int | None = None
        self.timed_out: bool = False
        self._accumulated: list[str] = []
        self._finished: bool = False

    def __aiter__(self) -> AsyncIterator[str]:
        return self._iterate()

    async def _iterate(self) -> AsyncIterator[str]:
        if self._finished:
            raise OpenFluxError("OpenFluxDeploy can only be iterated once")
        self._finished = True

        async for line in self._run:
            self._accumulated.append(line)
            yield line

        self.returncode = self._run.returncode
        self.timed_out = self._run.timed_out

        if self._transport != "cupsonline":
            logger.debug(
                "Skipping session parse: transport=%s has no session blob",
                self._transport,
            )
            return

        combined = "\n".join(self._accumulated)
        self.session_b64 = parse_session_b64(combined)
        if self.session_b64 is None:
            logger.info("OpenFlux session not found in deploy output")

    @property
    def tail(self) -> str:
        return self._run.tail

    def raise_if_failed(self) -> None:
        """Convenience for callers that treat non-zero as fatal."""
        if self.returncode is None:
            raise OpenFluxError("deploy not finished")
        if self.timed_out:
            raise OpenFluxDeployFailed(-1, tail=self.tail)
        if self.returncode != 0:
            raise OpenFluxDeployFailed(self.returncode, tail=self.tail)


async def run_openflux_deploy(
    runner: AnsibleRunner,
    playbook: Path,
    inventory: Path,
    secrets: Secrets,
    extra_vars: dict[str, Any] | None = None,
) -> OpenFluxDeploy:
    """Run the OpenFlux deploy playbook.

    The playbook is expected to dump recent service logs at the end
    (journalctl) so we can pick up the session for cupsonline. For other
    transports the dump is harmless — we just do not parse it.

    `secrets` is used only to know which transport is configured.
    """
    run = await runner.run(playbook, inventory, extra_vars=extra_vars)
    return OpenFluxDeploy(run, transport=secrets.openflux.transport)


# ---------- fetch with retry ----------


async def fetch_session_with_retry(
    fetch_logs: Callable[[], Any],
    *,
    retries: int = DEFAULT_RETRIES,
    delay: float = DEFAULT_RETRY_DELAY,
    sleep: Callable[[float], Any] = asyncio.sleep,
) -> str | None:
    """Call `fetch_logs` up to `retries` times; return first valid session.

    `fetch_logs` is an async callable returning log text (str).
    """
    last_error: Exception | None = None
    for attempt in range(1, retries + 1):
        try:
            text = await fetch_logs()
        except Exception as exc:  # noqa: BLE001 — deliberately broad
            last_error = exc
            logger.warning("openflux fetch attempt %d failed: %s", attempt, exc)
        else:
            session = parse_session_b64(text or "")
            if session:
                logger.info("OpenFlux session found on attempt %d", attempt)
                return session

        if attempt < retries:
            await sleep(delay)

    if last_error:
        logger.warning(
            "openflux fetch gave up after %d attempts: %s", retries, last_error
        )
    else:
        logger.warning("openflux session not found after %d attempts", retries)
    return None


# ---------- persistence ----------


def persist_session(store: SecretsStore, ip: str, session_b64: str) -> None:
    """Store session_b64 into secrets.openflux and save.

    No-op if the stored value is identical (avoids touching updated_at).
    """
    secrets = store.load(ip)
    if secrets.openflux.session_b64 == session_b64:
        logger.debug("OpenFlux session unchanged for %s", ip)
        return
    secrets.openflux.session_b64 = session_b64
    store.save(secrets)
    logger.info("Persisted new OpenFlux session for %s", ip)