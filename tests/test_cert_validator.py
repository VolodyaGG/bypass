"""Tests for vpnforge.cert_validator."""

from __future__ import annotations

import datetime as dt
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from freezegun import freeze_time

from vpnforge.cert_validator import (
    CertDomainMismatch,
    CertExpired,
    CertKeyMismatch,
    CertParseError,
    check_matches_domain,
    check_validity,
    parse_fullchain,
    parse_privkey,
    validate_cert_bytes,
    validate_cert_pair,
    verify_pair,
)
from vpnforge.models import CertInfo

# ---------- helpers to build certs ----------


def _mk_key() -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(ec.SECP256R1())


def _mk_cert(
    key: ec.EllipticCurvePrivateKey,
    cn: str,
    sans: list[str],
    not_before: dt.datetime,
    not_after: dt.datetime,
) -> x509.Certificate:
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)  # self-signed for tests
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
    )
    if sans:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(s) for s in sans]),
            critical=False,
        )
    return builder.sign(key, hashes.SHA256())


def _write_pem(path: Path, cert: x509.Certificate) -> None:
    path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))


def _write_chain(path: Path, certs: list[x509.Certificate]) -> None:
    path.write_bytes(b"".join(c.public_bytes(serialization.Encoding.PEM) for c in certs))


def _write_key(path: Path, key: ec.EllipticCurvePrivateKey) -> None:
    path.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )


@pytest.fixture()
def now() -> dt.datetime:
    return dt.datetime(2026, 9, 14, 12, 0, 0, tzinfo=dt.UTC)


@pytest.fixture()
def valid_cert(tmp_path: Path, now: dt.datetime) -> tuple[Path, Path]:
    key = _mk_key()
    cert = _mk_cert(
        key,
        cn="node1.example.com",
        sans=["node1.example.com"],
        not_before=now - dt.timedelta(days=1),
        not_after=now + dt.timedelta(days=89),
    )
    fullchain = tmp_path / "fullchain.pem"
    privkey = tmp_path / "privkey.pem"
    _write_pem(fullchain, cert)
    _write_key(privkey, key)
    return fullchain, privkey


# ---------- parse_fullchain ----------


def test_parse_fullchain_basic(valid_cert: tuple[Path, Path], now: dt.datetime) -> None:
    fullchain, _ = valid_cert
    with freeze_time(now):
        info = parse_fullchain(fullchain)
    assert info.subject_cn == "node1.example.com"
    assert "node1.example.com" in info.san_domains
    assert info.not_after > info.not_before
    assert len(info.sha256) == 64
    assert info.issuer_cn == "node1.example.com"  # self-signed


def test_parse_fullchain_returns_first_cert(tmp_path: Path, now: dt.datetime) -> None:
    """fullchain.pem = leaf + intermediate; we must return the leaf."""
    leaf_key = _mk_key()
    leaf = _mk_cert(
        leaf_key,
        cn="node1.example.com",
        sans=["node1.example.com"],
        not_before=now - dt.timedelta(days=1),
        not_after=now + dt.timedelta(days=89),
    )
    inter_key = _mk_key()
    inter = _mk_cert(
        inter_key,
        cn="Fake Intermediate",
        sans=[],
        not_before=now - dt.timedelta(days=10),
        not_after=now + dt.timedelta(days=365),
    )
    chain = tmp_path / "fullchain.pem"
    _write_chain(chain, [leaf, inter])
    with freeze_time(now):
        info = parse_fullchain(chain)
    assert info.subject_cn == "node1.example.com"


def test_parse_fullchain_no_san(tmp_path: Path, now: dt.datetime) -> None:
    key = _mk_key()
    cert = _mk_cert(
        key,
        cn="node1.example.com",
        sans=[],
        not_before=now - dt.timedelta(days=1),
        not_after=now + dt.timedelta(days=89),
    )
    p = tmp_path / "c.pem"
    _write_pem(p, cert)
    with freeze_time(now):
        info = parse_fullchain(p)
    assert info.san_domains == []
    assert info.subject_cn == "node1.example.com"


def test_parse_fullchain_garbage(tmp_path: Path) -> None:
    p = tmp_path / "c.pem"
    p.write_text("not a certificate", encoding="utf-8")
    with pytest.raises(CertParseError):
        parse_fullchain(p)


def test_parse_fullchain_missing_file(tmp_path: Path) -> None:
    with pytest.raises(CertParseError):
        parse_fullchain(tmp_path / "nope.pem")


def test_parse_fullchain_empty(tmp_path: Path) -> None:
    p = tmp_path / "empty.pem"
    p.write_text("", encoding="utf-8")
    with pytest.raises(CertParseError):
        parse_fullchain(p)


# ---------- parse_privkey ----------


def test_parse_privkey_ok(valid_cert: tuple[Path, Path]) -> None:
    _, privkey = valid_cert
    parse_privkey(privkey)  # no raise


def test_parse_privkey_garbage(tmp_path: Path) -> None:
    p = tmp_path / "k.pem"
    p.write_text("not a key", encoding="utf-8")
    with pytest.raises(CertParseError):
        parse_privkey(p)


def test_parse_privkey_encrypted(tmp_path: Path) -> None:
    key = _mk_key()
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(b"secret"),
    )
    p = tmp_path / "enc.pem"
    p.write_bytes(pem)
    with pytest.raises(CertParseError):
        parse_privkey(p)


# ---------- verify_pair ----------


def test_verify_pair_ok(valid_cert: tuple[Path, Path]) -> None:
    fullchain, privkey = valid_cert
    assert verify_pair(fullchain, privkey) is True


def test_verify_pair_mismatch(tmp_path: Path, now: dt.datetime) -> None:
    k1 = _mk_key()
    cert = _mk_cert(
        k1,
        cn="node1.example.com",
        sans=["node1.example.com"],
        not_before=now - dt.timedelta(days=1),
        not_after=now + dt.timedelta(days=89),
    )
    fullchain = tmp_path / "c.pem"
    _write_pem(fullchain, cert)

    k2 = _mk_key()
    privkey = tmp_path / "k.pem"
    _write_key(privkey, k2)

    with pytest.raises(CertKeyMismatch):
        verify_pair(fullchain, privkey)


def test_verify_pair_bad_cert(tmp_path: Path) -> None:
    fullchain = tmp_path / "c.pem"
    fullchain.write_text("nope", encoding="utf-8")
    key = _mk_key()
    privkey = tmp_path / "k.pem"
    _write_key(privkey, key)
    with pytest.raises(CertParseError):
        verify_pair(fullchain, privkey)


# ---------- check_matches_domain ----------


def _info(cn: str, sans: list[str], now: dt.datetime) -> CertInfo:
    return CertInfo(
        subject_cn=cn,
        san_domains=[s.lower() for s in sans],
        not_before=now - dt.timedelta(days=1),
        not_after=now + dt.timedelta(days=89),
        issuer_cn="LE",
        sha256="0" * 64,
    )


def test_domain_exact(now: dt.datetime) -> None:
    info = _info("node1.example.com", ["node1.example.com"], now)
    assert check_matches_domain(info, "node1.example.com") is True


def test_domain_case_insensitive_and_trailing_dot(now: dt.datetime) -> None:
    info = _info("node1.example.com", ["node1.example.com"], now)
    assert check_matches_domain(info, "NODE1.Example.COM.") is True


def test_domain_from_san_only(now: dt.datetime) -> None:
    info = _info("ignored", ["node1.example.com"], now)
    assert check_matches_domain(info, "node1.example.com") is True


def test_domain_wildcard_match(now: dt.datetime) -> None:
    info = _info("*.example.com", ["*.example.com"], now)
    assert check_matches_domain(info, "node1.example.com") is True


def test_domain_wildcard_does_not_match_root(now: dt.datetime) -> None:
    info = _info("*.example.com", ["*.example.com"], now)
    with pytest.raises(CertDomainMismatch):
        check_matches_domain(info, "example.com")


def test_domain_wildcard_single_label_only(now: dt.datetime) -> None:
    info = _info("*.example.com", ["*.example.com"], now)
    with pytest.raises(CertDomainMismatch):
        check_matches_domain(info, "a.b.example.com")


def test_domain_mismatch(now: dt.datetime) -> None:
    info = _info("node1.example.com", ["node1.example.com"], now)
    with pytest.raises(CertDomainMismatch):
        check_matches_domain(info, "other.example.com")


def test_domain_empty(now: dt.datetime) -> None:
    info = _info("node1.example.com", ["node1.example.com"], now)
    with pytest.raises(CertDomainMismatch):
        check_matches_domain(info, "   ")


# ---------- check_validity ----------


def test_validity_ok(now: dt.datetime) -> None:
    info = _info("x", ["x"], now)
    check_validity(info, now=now)


def test_validity_expired(now: dt.datetime) -> None:
    info = _info("x", ["x"], now)
    with pytest.raises(CertExpired):
        check_validity(info, now=info.not_after + dt.timedelta(seconds=1))


def test_validity_not_yet(now: dt.datetime) -> None:
    info = _info("x", ["x"], now)
    with pytest.raises(CertExpired):
        check_validity(info, now=info.not_before - dt.timedelta(seconds=1))


def test_validity_boundary_not_after_is_exclusive(now: dt.datetime) -> None:
    info = _info("x", ["x"], now)
    with pytest.raises(CertExpired):
        check_validity(info, now=info.not_after)


def test_validity_naive_now_treated_as_utc(now: dt.datetime) -> None:
    info = _info("x", ["x"], now)
    naive = now.replace(tzinfo=None)
    check_validity(info, now=naive)


def test_validate_cert_pair_ok(valid_cert: tuple[Path, Path]) -> None:
    fullchain, privkey = valid_cert
    with freeze_time("2026-09-14T12:00:00Z"):
        info = validate_cert_pair(fullchain, privkey, "node1.example.com")
    assert info.subject_cn == "node1.example.com"


def test_validate_cert_bytes_ok(valid_cert: tuple[Path, Path]) -> None:
    fullchain, privkey = valid_cert
    with freeze_time("2026-09-14T12:00:00Z"):
        info = validate_cert_bytes(
            fullchain.read_bytes(), privkey.read_bytes(), "node1.example.com"
        )
    assert info.sha256
