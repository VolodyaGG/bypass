"""Tests for vpnforge.dns_manager."""

from __future__ import annotations

import json as _json
import logging

import pytest
import responses

from vpnforge.dns_manager import (
    CF_API_BASE,
    CFAuthError,
    CFError,
    CFRecordError,
    CFTransientError,
    CFZoneNotFound,
    CloudflareDNS,
    _mask,
    _no_wait,
)

TOKEN = "super-secret-token-1234567890"
ZONE = "example.com"
ZONE_ID = "zone-abc"
FQDN = "node1.example.com"
IP = "1.2.3.4"


# ---------- helpers ----------


def _cf_ok(result: object) -> dict:
    return {"success": True, "errors": [], "messages": [], "result": result}


def _cf_err(code: int, message: str) -> dict:
    return {"success": False, "errors": [{"code": code, "message": message}]}


@pytest.fixture()
def cf() -> CloudflareDNS:
    """Fast client: no sleeps between retries."""
    return CloudflareDNS(TOKEN, wait_strategy=_no_wait)


# ---------- constructor ----------


def test_constructor_rejects_empty_token() -> None:
    with pytest.raises(CFAuthError):
        CloudflareDNS("")


def test_constructor_sets_auth_header(cf: CloudflareDNS) -> None:
    assert cf._session.headers["Authorization"] == f"Bearer {TOKEN}"


def test_token_masked_in_logs(caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level(logging.DEBUG, logger="vpnforge.dns_manager"):
        CloudflareDNS(TOKEN)
    assert TOKEN not in caplog.text
    assert "supe" in caplog.text


def test_mask_empty() -> None:
    assert _mask("") == "<empty>"


def test_mask_short() -> None:
    assert _mask("abc") == "***"


def test_mask_long() -> None:
    m = _mask("abcdefghijklmnop")
    assert "abcdefghijklmnop" not in m
    assert m.startswith("abcd")
    assert m.endswith("mnop")


# ---------- resolve_zone_id ----------


@responses.activate
def test_resolve_zone_id_ok(cf: CloudflareDNS) -> None:
    responses.add(
        responses.GET,
        f"{CF_API_BASE}/zones",
        json=_cf_ok([{"id": ZONE_ID, "name": ZONE}]),
        status=200,
    )
    assert cf.resolve_zone_id(ZONE) == ZONE_ID


@responses.activate
def test_resolve_zone_id_case_insensitive(cf: CloudflareDNS) -> None:
    responses.add(
        responses.GET,
        f"{CF_API_BASE}/zones",
        json=_cf_ok([{"id": ZONE_ID, "name": "Example.COM"}]),
        status=200,
    )
    assert cf.resolve_zone_id("  Example.com.  ") == ZONE_ID


@responses.activate
def test_resolve_zone_id_not_found(cf: CloudflareDNS) -> None:
    responses.add(
        responses.GET,
        f"{CF_API_BASE}/zones",
        json=_cf_ok([]),
        status=200,
    )
    with pytest.raises(CFZoneNotFound):
        cf.resolve_zone_id(ZONE)


@responses.activate
def test_resolve_zone_id_ignores_other_zones(cf: CloudflareDNS) -> None:
    responses.add(
        responses.GET,
        f"{CF_API_BASE}/zones",
        json=_cf_ok([{"id": "other", "name": "other.com"}]),
        status=200,
    )
    with pytest.raises(CFZoneNotFound):
        cf.resolve_zone_id(ZONE)


def test_resolve_zone_id_empty(cf: CloudflareDNS) -> None:
    with pytest.raises(CFZoneNotFound):
        cf.resolve_zone_id("   ")


# ---------- upsert: create path ----------


@responses.activate
def test_upsert_creates_when_missing(cf: CloudflareDNS) -> None:
    responses.add(
        responses.GET,
        f"{CF_API_BASE}/zones/{ZONE_ID}/dns_records",
        json=_cf_ok([]),
        status=200,
    )
    responses.add(
        responses.POST,
        f"{CF_API_BASE}/zones/{ZONE_ID}/dns_records",
        json=_cf_ok({"id": "rec-1"}),
        status=200,
    )

    record_id = cf.upsert_a_record(ZONE_ID, FQDN, IP)
    assert record_id == "rec-1"

    body = responses.calls[-1].request.body
    assert body is not None
    payload = _json.loads(body)
    assert payload == {
        "type": "A",
        "name": FQDN,
        "content": IP,
        "ttl": 60,
        "proxied": False,
    }


# ---------- upsert: update path ----------


@responses.activate
def test_upsert_updates_when_exists(cf: CloudflareDNS) -> None:
    responses.add(
        responses.GET,
        f"{CF_API_BASE}/zones/{ZONE_ID}/dns_records",
        json=_cf_ok([{"id": "rec-1", "type": "A", "name": FQDN}]),
        status=200,
    )
    responses.add(
        responses.PUT,
        f"{CF_API_BASE}/zones/{ZONE_ID}/dns_records/rec-1",
        json=_cf_ok({"id": "rec-1"}),
        status=200,
    )

    record_id = cf.upsert_a_record(ZONE_ID, FQDN, IP)
    assert record_id == "rec-1"
    assert responses.calls[-1].request.method == "PUT"


# ---------- upsert: forced proxied=false ----------


@responses.activate
def test_upsert_forces_proxied_false(cf: CloudflareDNS) -> None:
    responses.add(
        responses.GET,
        f"{CF_API_BASE}/zones/{ZONE_ID}/dns_records",
        json=_cf_ok([]),
        status=200,
    )
    responses.add(
        responses.POST,
        f"{CF_API_BASE}/zones/{ZONE_ID}/dns_records",
        json=_cf_ok({"id": "rec-1"}),
        status=200,
    )

    cf.upsert_a_record(ZONE_ID, FQDN, IP, proxied=True)
    body = responses.calls[-1].request.body
    assert body is not None
    payload = _json.loads(body)
    assert payload["proxied"] is False


# ---------- upsert: empty fqdn ----------


def test_upsert_empty_fqdn(cf: CloudflareDNS) -> None:
    with pytest.raises(CFRecordError):
        cf.upsert_a_record(ZONE_ID, "   ", IP)


# ---------- error mapping ----------


@responses.activate
def test_auth_401(cf: CloudflareDNS) -> None:
    responses.add(
        responses.GET,
        f"{CF_API_BASE}/zones",
        json=_cf_err(10000, "Authentication error"),
        status=401,
    )
    with pytest.raises(CFAuthError):
        cf.resolve_zone_id(ZONE)


@responses.activate
def test_auth_403(cf: CloudflareDNS) -> None:
    responses.add(
        responses.GET,
        f"{CF_API_BASE}/zones",
        json=_cf_err(10000, "Forbidden"),
        status=403,
    )
    with pytest.raises(CFAuthError):
        cf.resolve_zone_id(ZONE)


@responses.activate
def test_bad_request_becomes_record_error(cf: CloudflareDNS) -> None:
    responses.add(
        responses.GET,
        f"{CF_API_BASE}/zones/{ZONE_ID}/dns_records",
        json=_cf_err(9003, "bad"),
        status=400,
    )
    with pytest.raises(CFRecordError):
        cf.upsert_a_record(ZONE_ID, FQDN, IP)


@responses.activate
def test_success_false_maps_to_error(cf: CloudflareDNS) -> None:
    responses.add(
        responses.GET,
        f"{CF_API_BASE}/zones",
        json=_cf_err(9999, "nope"),
        status=200,
    )
    with pytest.raises(CFError):
        cf.resolve_zone_id(ZONE)


@responses.activate
def test_non_json_response(cf: CloudflareDNS) -> None:
    responses.add(
        responses.GET,
        f"{CF_API_BASE}/zones",
        body="<html>oops</html>",
        status=200,
        content_type="text/html",
    )
    with pytest.raises(CFError):
        cf.resolve_zone_id(ZONE)


@responses.activate
def test_record_missing_id_in_response(cf: CloudflareDNS) -> None:
    responses.add(
        responses.GET,
        f"{CF_API_BASE}/zones/{ZONE_ID}/dns_records",
        json=_cf_ok([]),
        status=200,
    )
    responses.add(
        responses.POST,
        f"{CF_API_BASE}/zones/{ZONE_ID}/dns_records",
        json=_cf_ok({}),
        status=200,
    )
    with pytest.raises(CFRecordError):
        cf.upsert_a_record(ZONE_ID, FQDN, IP)


# ---------- retry ----------


@responses.activate
def test_retries_on_500_then_succeeds(cf: CloudflareDNS) -> None:
    responses.add(responses.GET, f"{CF_API_BASE}/zones", status=500)
    responses.add(responses.GET, f"{CF_API_BASE}/zones", status=503)
    responses.add(
        responses.GET,
        f"{CF_API_BASE}/zones",
        json=_cf_ok([{"id": ZONE_ID, "name": ZONE}]),
        status=200,
    )
    assert cf.resolve_zone_id(ZONE) == ZONE_ID
    assert len(responses.calls) == 3


@responses.activate
def test_retries_on_429(cf: CloudflareDNS) -> None:
    responses.add(responses.GET, f"{CF_API_BASE}/zones", status=429)
    responses.add(
        responses.GET,
        f"{CF_API_BASE}/zones",
        json=_cf_ok([{"id": ZONE_ID, "name": ZONE}]),
        status=200,
    )
    assert cf.resolve_zone_id(ZONE) == ZONE_ID
    assert len(responses.calls) == 2


@responses.activate
def test_gives_up_after_retries_and_raises_transient(cf: CloudflareDNS) -> None:
    for _ in range(10):
        responses.add(responses.GET, f"{CF_API_BASE}/zones", status=500)
    with pytest.raises(CFTransientError):
        cf.resolve_zone_id(ZONE)
    assert len(responses.calls) == 4  # default max_attempts


@responses.activate
def test_custom_max_attempts() -> None:
    cf = CloudflareDNS(TOKEN, wait_strategy=_no_wait, max_attempts=2)
    for _ in range(10):
        responses.add(responses.GET, f"{CF_API_BASE}/zones", status=500)
    with pytest.raises(CFTransientError):
        cf.resolve_zone_id(ZONE)
    assert len(responses.calls) == 2


@responses.activate
def test_network_error_retried(cf: CloudflareDNS) -> None:
    responses.add(
        responses.GET,
        f"{CF_API_BASE}/zones",
        body=ConnectionError("boom"),
    )
    responses.add(
        responses.GET,
        f"{CF_API_BASE}/zones",
        json=_cf_ok([{"id": ZONE_ID, "name": ZONE}]),
        status=200,
    )
    assert cf.resolve_zone_id(ZONE) == ZONE_ID
    assert len(responses.calls) == 2