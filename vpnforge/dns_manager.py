"""Cloudflare DNS API client.

We only need two things from CF:
  * resolve zone_id by root domain (cached in Secrets.cloudflare.zone_id),
  * upsert an A record for node<N>.<domain> -> VPS IP, proxied=false, TTL=60.

Token never goes into logs. All HTTP errors map to typed exceptions.
Retry is done at runtime via `Retrying` so tests can disable sleeps
without monkeypatching module-level imported symbols.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from typing import Any

import requests
from tenacity import (
    Retrying,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
)

logger = logging.getLogger(__name__)

CF_API_BASE = "https://api.cloudflare.com/client/v4"

# Default retry policy. Tests override per-instance.
_DEFAULT_MAX_ATTEMPTS = 4


class CFError(Exception):
    """Base class for Cloudflare errors."""


class CFAuthError(CFError):
    """Token invalid or lacks permissions (HTTP 401/403)."""


class CFZoneNotFound(CFError):
    """No zone matches the requested root domain."""


class CFRecordError(CFError):
    """DNS record lookup/create/update failed."""


class CFTransientError(CFError):
    """5xx / 429 / network failure after all retries exhausted."""


class _Retryable(Exception):
    """Internal marker for tenacity retry — never escapes CloudflareDNS."""


def _mask(token: str) -> str:
    if not token:
        return "<empty>"
    if len(token) <= 8:
        return "*" * len(token)
    return f"{token[:4]}…{token[-4:]}"


def _no_wait(*_: Any, **__: Any) -> float:
    return 0.0


class CloudflareDNS:
    """Thin wrapper around CF DNS API.

    Not thread-safe (a single requests.Session is shared).
    """

    def __init__(
        self,
        api_token: str,
        *,
        timeout: float = 15.0,
        session: requests.Session | None = None,
        max_attempts: int = _DEFAULT_MAX_ATTEMPTS,
        wait_strategy: Callable[..., float] | None = None,
    ) -> None:
        if not api_token:
            raise CFAuthError("Cloudflare API token is empty")

        self._token = api_token
        self._timeout = timeout
        self._max_attempts = max_attempts
        self._wait_strategy: Callable[..., float] = wait_strategy or wait_exponential(
            multiplier=0.5, min=0.5, max=4
        )

        self._session = session or requests.Session()
        self._session.headers.update(
            {
                "Authorization": f"Bearer {api_token}",
                "Content-Type": "application/json",
                "Accept": "application/json",
            }
        )
        logger.debug("CloudflareDNS initialized with token %s", _mask(api_token))

    # ---------- public ----------

    def resolve_zone_id(self, root_domain: str) -> str:
        """Return zone_id for root_domain (e.g. 'example.com')."""
        root_domain = root_domain.strip().lower().rstrip(".")
        if not root_domain:
            raise CFZoneNotFound("root domain is empty")

        payload = self._request(
            "GET",
            f"{CF_API_BASE}/zones",
            params={"name": root_domain, "per_page": 50},
        )
        result = payload.get("result") or []
        for zone in result:
            if str(zone.get("name", "")).lower() == root_domain:
                zone_id = zone.get("id")
                if isinstance(zone_id, str) and zone_id:
                    logger.info("Resolved zone_id for %s", root_domain)
                    return zone_id
        raise CFZoneNotFound(f"zone not found for {root_domain!r}")

    def upsert_a_record(
        self,
        zone_id: str,
        fqdn: str,
        ip: str,
        *,
        ttl: int = 60,
        proxied: bool = False,
    ) -> str:
        """Create or update an A record. Returns record_id."""
        if proxied:
            # We deliberately force proxied=false: Reality/Hysteria need real IP.
            logger.warning("proxied=true requested; forcing proxied=false for %s", fqdn)
            proxied = False

        fqdn = fqdn.strip().lower().rstrip(".")
        if not fqdn:
            raise CFRecordError("fqdn is empty")

        existing = self._find_record(zone_id, fqdn)

        body: dict[str, Any] = {
            "type": "A",
            "name": fqdn,
            "content": ip,
            "ttl": ttl,
            "proxied": proxied,
        }

        if existing is None:
            payload = self._request(
                "POST",
                f"{CF_API_BASE}/zones/{zone_id}/dns_records",
                json=body,
            )
            action = "created"
        else:
            record_id = existing["id"]
            payload = self._request(
                "PUT",
                f"{CF_API_BASE}/zones/{zone_id}/dns_records/{record_id}",
                json=body,
            )
            action = "updated"

        result = payload.get("result") or {}
        new_id = result.get("id")
        if not isinstance(new_id, str) or not new_id:
            raise CFRecordError(f"CF did not return record id after {action} {fqdn}")

        logger.info("DNS record %s %s -> %s", action, fqdn, ip)
        return new_id

    # ---------- internals ----------

    def _find_record(self, zone_id: str, fqdn: str) -> dict[str, Any] | None:
        payload = self._request(
            "GET",
            f"{CF_API_BASE}/zones/{zone_id}/dns_records",
            params={"type": "A", "name": fqdn, "per_page": 50},
        )
        result = payload.get("result") or []
        for rec in result:
            if (
                str(rec.get("type", "")).upper() == "A"
                and str(rec.get("name", "")).lower().rstrip(".") == fqdn
                and isinstance(rec, dict)
            ):
                return rec
        return None

    def _request(
        self,
        method: str,
        url: str,
        *,
        params: dict[str, Any] | None = None,
        json: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        retryer: Retrying = Retrying(
            reraise=True,
            stop=stop_after_attempt(self._max_attempts),
            wait=self._wait_strategy,
            retry=retry_if_exception_type((_Retryable, requests.RequestException)),
        )
        try:
            return retryer(
                self._request_once, method, url, params=params, json=json
            )
        except _Retryable as exc:
            raise CFTransientError(f"Cloudflare transient failure: {exc}") from exc

    def _request_once(
        self,
        method: str,
        url: str,
        *,
        params: dict[str, Any] | None = None,
        json: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        try:
            resp = self._session.request(
                method, url, params=params, json=json, timeout=self._timeout
            )
        except Exception as exc:
            logger.warning("CF network error: %s", exc)
            raise _Retryable(str(exc)) from exc

        status = resp.status_code

        if status in (401, 403):
            raise CFAuthError(
                f"Cloudflare auth failed (HTTP {status}); check token permissions"
            )

        if status >= 500:
            logger.warning("CF transient HTTP %s", status)
            raise _Retryable(f"HTTP {status}")

        if status == 429:
            logger.warning("CF rate limit (429)")
            raise _Retryable("HTTP 429")

        try:
            payload = resp.json()
        except ValueError as exc:
            raise CFError(f"CF returned non-JSON (HTTP {status})") from exc

        if not isinstance(payload, dict):
            raise CFError(f"CF returned unexpected payload (HTTP {status})")

        if not payload.get("success", False):
            errors = payload.get("errors") or []
            msg = (
                "; ".join(
                    f"{e.get('code', '?')}: {e.get('message', '')}" for e in errors
                )
                or f"HTTP {status}"
            )
            if status in (400, 404):
                raise CFRecordError(f"CF rejected request: {msg}")
            raise CFError(f"CF error: {msg}")

        return payload
