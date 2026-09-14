"""Cryptographic helpers. All randomness comes from `secrets`."""

from __future__ import annotations

import base64
import secrets
import uuid

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519


def _b64url_nopad(raw: bytes) -> str:
    """Base64url without padding."""
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def generate_uuid4() -> str:
    """Random UUIDv4 as canonical string."""
    return str(uuid.uuid4())


def generate_x25519_keypair() -> tuple[str, str]:
    """Return (private_key_b64url, public_key_b64url)."""
    private_key = x25519.X25519PrivateKey.generate()
    private_raw = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_raw = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return _b64url_nopad(private_raw), _b64url_nopad(public_raw)


def generate_short_id(length: int = 8) -> str:
    """Hex string of even length (default 8 chars = 4 bytes)."""
    if length <= 0 or length % 2 != 0:
        raise ValueError("short_id length must be positive and even")
    return secrets.token_hex(length // 2)


def generate_password(length: int = 24) -> str:
    """URL-safe password without ambiguous characters."""
    alphabet = "abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"
    return "".join(secrets.choice(alphabet) for _ in range(length))


def generate_sub_token() -> str:
    """32-hex-char subscription token (16 bytes)."""
    return secrets.token_hex(16)


def generate_obfs_password() -> str:
    """Obfuscation password for Hysteria 2."""
    return _b64url_nopad(secrets.token_bytes(24))