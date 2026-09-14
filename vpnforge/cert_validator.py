"""X.509 certificate validation for user-supplied fullchain + privkey.

We do NOT issue certificates — user uploads LE-issued files. We only:
  * parse them,
  * check the key matches the cert,
  * check the requested domain is covered by CN/SAN,
  * check the cert is currently valid (not_before <= now < not_after).
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from cryptography.x509.oid import ExtensionOID

from vpnforge.models import CertInfo


class CertError(Exception):
    """Base class for certificate validation errors. Messages are in Russian."""


class CertParseError(CertError):
    """Файл не удалось распарсить как PEM/DER."""


class CertKeyMismatch(CertError):
    """Приватный ключ не соответствует сертификату."""


class CertDomainMismatch(CertError):
    """Домен не покрыт CN/SAN сертификата."""


class CertExpired(CertError):
    """Сертификат просрочен или ещё не вступил в силу."""


# ---------- parsing ----------


def _load_pem(path: Path) -> bytes:
    try:
        return path.read_bytes()
    except OSError as exc:
        raise CertParseError(f"не удалось прочитать файл {path}: {exc}") from exc


def parse_fullchain(path: Path) -> CertInfo:
    """Parse the *leaf* certificate from a PEM fullchain file.

    A fullchain typically contains leaf first, then intermediates. We only
    care about the leaf for domain/validity checks.
    """
    raw = _load_pem(path)
    try:
        # load_pem_x509_certificates returns list; leaf is [0]
        certs = x509.load_pem_x509_certificates(raw)
    except ValueError as exc:
        raise CertParseError(f"не удалось распарсить сертификат {path}: {exc}") from exc

    if not certs:
        raise CertParseError(f"в файле {path} нет сертификатов")

    leaf = certs[0]

    subject_cn = _extract_cn(leaf.subject) or ""
    issuer_cn = _extract_cn(leaf.issuer) or ""

    san_domains = _extract_san(leaf)

    sha256 = hashlib.sha256(
        leaf.public_bytes(serialization.Encoding.DER)
    ).hexdigest()

    return CertInfo(
        subject_cn=subject_cn,
        san_domains=san_domains,
        not_before=leaf.not_valid_before_utc,
        not_after=leaf.not_valid_after_utc,
        issuer_cn=issuer_cn,
        sha256=sha256,
    )


def parse_privkey(path: Path) -> None:
    """Validate that the file is a parseable unencrypted PEM private key."""
    raw = _load_pem(path)
    try:
        serialization.load_pem_private_key(raw, password=None)
    except (ValueError, TypeError) as exc:
        raise CertParseError(f"не удалось распарсить приватный ключ {path}: {exc}") from exc


# ---------- pair verification ----------


def verify_pair(fullchain: Path, privkey: Path) -> bool:
    """Return True if the leaf cert's public key matches the private key."""
    cert_raw = _load_pem(fullchain)
    key_raw = _load_pem(privkey)

    try:
        leaf = x509.load_pem_x509_certificates(cert_raw)[0]
    except (ValueError, IndexError) as exc:
        raise CertParseError(f"не удалось распарсить сертификат {fullchain}: {exc}") from exc

    try:
        priv = serialization.load_pem_private_key(key_raw, password=None)
    except (ValueError, TypeError) as exc:
        raise CertParseError(f"не удалось распарсить ключ {privkey}: {exc}") from exc

    if not _keys_match(leaf.public_key(), priv.public_key()):
        raise CertKeyMismatch("приватный ключ не соответствует сертификату")
    return True


# ---------- domain check ----------


def check_matches_domain(info: CertInfo, domain: str) -> bool:
    """Check that `domain` is covered by CN or SAN. Supports one wildcard level."""
    domain = domain.strip().lower().rstrip(".")
    if not domain:
        raise CertDomainMismatch("домен пустой")

    candidates: list[str] = []
    if info.subject_cn:
        candidates.append(info.subject_cn.lower().rstrip("."))
    for d in info.san_domains:
        candidates.append(d.lower().rstrip("."))

    if not any(_domain_matches(domain, c) for c in candidates):
        raise CertDomainMismatch(
            f"домен {domain!r} не покрыт сертификатом "
            f"(CN={info.subject_cn!r}, SAN={info.san_domains})"
        )
    return True


def check_validity(info: CertInfo, now: datetime | None = None) -> None:
    """Raise CertExpired if now is outside [not_before, not_after)."""
    if now is None:
        now = datetime.now(timezone.utc)
    if now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)

    if now < info.not_before:
        raise CertExpired(
            f"сертификат ещё не вступил в силу (not_before={info.not_before.isoformat()})"
        )
    if now >= info.not_after:
        raise CertExpired(
            f"сертификат просрочен (not_after={info.not_after.isoformat()})"
        )


# ---------- internals ----------


def _extract_cn(name: x509.Name) -> str | None:
    attrs = name.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
    if not attrs:
        return None
    value = attrs[0].value
    return value if isinstance(value, str) else None


def _extract_san(cert: x509.Certificate) -> list[str]:
    try:
        ext = cert.extensions.get_extension_for_oid(
            ExtensionOID.SUBJECT_ALTERNATIVE_NAME
        )
    except x509.ExtensionNotFound:
        return []
    san = ext.value
    if not isinstance(san, x509.SubjectAlternativeName):
        return []
    return [str(d).strip().lower() for d in san.get_values_for_type(x509.DNSName)]


def _keys_match(pub_a: object, pub_b: object) -> bool:
    """Compare two public keys by DER encoding (format-agnostic)."""
    try:
        a = pub_a.public_bytes(  # type: ignore[attr-defined]
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        b = pub_b.public_bytes(  # type: ignore[attr-defined]
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    except AttributeError:
        return False
    return a == b


def _domain_matches(domain: str, pattern: str) -> bool:
    """RFC 6125-style match with single-level wildcard support.

    `*.example.com` matches `foo.example.com` but not `a.b.example.com`
    and not `example.com`.
    """
    if pattern == domain:
        return True
    if pattern.startswith("*."):
        suffix = pattern[2:]
        if not domain.endswith("." + suffix):
            return False
        # only one label before the suffix
        head = domain[: -(len(suffix) + 1)]
        return "." not in head and head != ""
    return False