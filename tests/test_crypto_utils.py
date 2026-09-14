"""Tests for vpnforge.crypto_utils."""

from __future__ import annotations

import base64
import re

import pytest

from vpnforge import crypto_utils


def _b64url_decode(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


def test_generate_uuid4_format() -> None:
    u = crypto_utils.generate_uuid4()
    assert re.fullmatch(
        r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}", u
    )


def test_generate_uuid4_unique() -> None:
    assert len({crypto_utils.generate_uuid4() for _ in range(1000)}) == 1000


def test_x25519_keypair_roundtrip() -> None:
    priv, pub = crypto_utils.generate_x25519_keypair()
    assert _b64url_decode(priv).__len__() == 32
    assert _b64url_decode(pub).__len__() == 32
    assert "=" not in priv and "=" not in pub


def test_x25519_keypair_unique() -> None:
    pairs = {crypto_utils.generate_x25519_keypair() for _ in range(50)}
    assert len(pairs) == 50


def test_short_id_default_length() -> None:
    sid = crypto_utils.generate_short_id()
    assert len(sid) == 8
    assert re.fullmatch(r"[0-9a-f]{8}", sid)


def test_short_id_rejects_odd() -> None:
    with pytest.raises(ValueError):
        crypto_utils.generate_short_id(7)


def test_short_id_rejects_zero() -> None:
    with pytest.raises(ValueError):
        crypto_utils.generate_short_id(0)


def test_password_length_and_alphabet() -> None:
    p = crypto_utils.generate_password(32)
    assert len(p) == 32
    assert re.fullmatch(r"[A-Za-z0-9]+", p)
    # ambiguous chars excluded
    assert not set(p) & set("0O1lI")


def test_sub_token_is_32_hex() -> None:
    t = crypto_utils.generate_sub_token()
    assert len(t) == 32
    assert re.fullmatch(r"[0-9a-f]{32}", t)


def test_obfs_password_urlsafe() -> None:
    p = crypto_utils.generate_obfs_password()
    assert "=" not in p
    assert _b64url_decode(p)
