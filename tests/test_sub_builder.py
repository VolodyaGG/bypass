"""Tests for vpnforge.sub_builder."""

from __future__ import annotations

import base64
import json
from urllib.parse import parse_qs, urlparse

import pytest

from vpnforge.models import (
    Client,
    ClientRoutingConfig,
    Hysteria2Config,
    ProtocolFlags,
    RealityConfig,
    Secrets,
)
from vpnforge.sub_builder import (
    SubBuildError,
    build_clients_json,
    build_hysteria_url,
    build_subscription_for_client,
    build_vless_url,
    build_xray_client_config,
    dump_clients_json,
    encode_subscription,
)

UUID_A = "11111111-1111-4111-8111-111111111111"
UUID_B = "22222222-2222-4222-8222-222222222222"


def _reality() -> RealityConfig:
    return RealityConfig(
        private_key="PRIVATE_KEY_MUST_NOT_LEAK",
        public_key="PUBLIC_KEY_OK_TO_LEAK",
        short_id="deadbeef",
        dest="www.microsoft.com:443",
        server_name="www.microsoft.com",
        fingerprint="chrome",
        spider_x="/",
        xhttp_path="/",
        xhttp_mode="packet-up",
    )


def _hysteria() -> Hysteria2Config:
    return Hysteria2Config(
        obfs_password="obfs-secret",
        masquerade_url="https://apple.com",
    )


def _client(
    label: str,
    uuid: str,
    user: str,
    pw: str,
    *,
    disabled: bool = False,
    sub_token: str = "a" * 32,
    client_id: str = "cid-1",
) -> Client:
    return Client(
        id=client_id,
        label=label,
        sub_token=sub_token,
        vless_uuid=uuid,
        hysteria_user=user,
        hysteria_pass=pw,
        disabled=disabled,
    )


def _secrets(
    clients: list[Client],
    *,
    domain: str | None = "node1.example.com",
    with_reality: bool = True,
    with_hysteria: bool = True,
) -> Secrets:
    return Secrets(
        ip="1.2.3.4",
        domain=domain,
        protocols=ProtocolFlags(
            vless_reality=with_reality,
            hysteria2=with_hysteria,
            openflux=False,
        ),
        reality=_reality() if with_reality else None,
        hysteria2=_hysteria() if with_hysteria else None,
        clients=clients,
    )


# ---------- build_vless_url ----------


def test_vless_url_basic_shape() -> None:
    c = _client("Вася", UUID_A, "vasya", "pw")
    s = _secrets([c])
    url = build_vless_url(s, c)

    assert url.startswith(f"vless://{UUID_A}@node1.example.com:443?")
    assert "#" in url


def test_vless_url_query_params() -> None:
    c = _client("Вася", UUID_A, "vasya", "pw")
    url = build_vless_url(_secrets([c]), c)

    parsed = urlparse(url)
    q = parse_qs(parsed.query, keep_blank_values=True)

    assert q["type"] == ["tcp"]
    assert q["security"] == ["reality"]
    assert q["flow"] == ["xtls-rprx-vision"]
    assert q["pbk"] == ["PUBLIC_KEY_OK_TO_LEAK"]
    assert q["fp"] == ["chrome"]
    assert q["sni"] == ["www.microsoft.com"]
    assert q["sid"] == ["deadbeef"]
    assert q["spx"] == ["/"]
    assert "path" not in q
    assert "mode" not in q


def test_vless_url_does_not_contain_private_key() -> None:
    c = _client("Вася", UUID_A, "vasya", "pw")
    url = build_vless_url(_secrets([c]), c)
    assert "PRIVATE_KEY_MUST_NOT_LEAK" not in url


def test_vless_url_falls_back_to_ip_without_domain() -> None:
    c = _client("Вася", UUID_A, "vasya", "pw")
    s = _secrets([c], domain=None, with_hysteria=False)
    url = build_vless_url(s, c)
    assert url.startswith(f"vless://{UUID_A}@1.2.3.4:443?")


def test_vless_url_fragment_contains_label() -> None:
    c = _client("Вася", UUID_A, "vasya", "pw")
    url = build_vless_url(_secrets([c]), c)
    assert "Вася" in url or "%D0%92%D0%B0%D1%81%D1%8F" in url


def test_vless_url_fragment_encodes_spaces() -> None:
    c = _client("Vasya Pupkin", UUID_A, "vasya", "pw")
    url = build_vless_url(_secrets([c]), c)
    # space must NOT become '+'
    assert "+" not in url.split("#", 1)[1]
    assert "%20" in url.split("#", 1)[1]


def test_vless_url_slash_encoded_in_params() -> None:
    """The Reality spider path remains escaped in the raw URL."""
    c = _client("Vasya", UUID_A, "vasya", "pw")
    url = build_vless_url(_secrets([c]), c)
    raw_query = url.split("?", 1)[1].split("#", 1)[0]
    assert "spx=%2F" in raw_query


def test_vless_url_raises_without_reality() -> None:
    c = _client("Vasya", UUID_A, "vasya", "pw")
    s = _secrets([c], with_reality=False)
    with pytest.raises(SubBuildError):
        build_vless_url(s, c)


# ---------- build_hysteria_url ----------


def test_hysteria_url_basic_shape() -> None:
    c = _client("Вася", UUID_A, "vasya", "pw-secret")
    url = build_hysteria_url(_secrets([c]), c)
    assert url.startswith("hysteria2://vasya%3Apw-secret@node1.example.com:443/?")
    assert "#" in url


def test_hysteria_url_query_params() -> None:
    c = _client("Вася", UUID_A, "vasya", "pw")
    url = build_hysteria_url(_secrets([c]), c)
    parsed = urlparse(url)
    q = parse_qs(parsed.query, keep_blank_values=True)

    assert q["sni"] == ["node1.example.com"]
    assert q["insecure"] == ["0"]
    assert q["obfs"] == ["salamander"]
    assert q["obfs-password"] == ["obfs-secret"]


def test_hysteria_url_requires_domain() -> None:
    c = _client("Вася", UUID_A, "vasya", "pw")
    s = _secrets([c], domain=None)
    with pytest.raises(SubBuildError, match="requires a domain"):
        build_hysteria_url(s, c)


def test_hysteria_url_raises_without_config() -> None:
    c = _client("Вася", UUID_A, "vasya", "pw")
    s = _secrets([c], with_hysteria=False)
    with pytest.raises(SubBuildError):
        build_hysteria_url(s, c)


def test_hysteria_url_encodes_special_chars_in_password() -> None:
    c = _client("Вася", UUID_A, "vasya", "p/w:d?e")
    url = build_hysteria_url(_secrets([c]), c)
    # password must be percent-encoded in the userinfo part
    userinfo = url.split("://", 1)[1].split("@", 1)[0]
    assert userinfo == "vasya%3Ap%2Fw%3Ad%3Fe"


# ---------- build_subscription_for_client ----------


def test_subscription_both_protocols() -> None:
    c = _client("Вася", UUID_A, "vasya", "pw")
    urls = build_subscription_for_client(_secrets([c]), c)
    assert len(urls) == 2
    assert urls[0].startswith("vless://")
    assert urls[1].startswith("hysteria2://")


def test_subscription_only_vless() -> None:
    c = _client("Вася", UUID_A, "vasya", "pw")
    s = _secrets([c], with_hysteria=False)
    urls = build_subscription_for_client(s, c)
    assert len(urls) == 1
    assert urls[0].startswith("vless://")


def test_subscription_only_hysteria() -> None:
    c = _client("Вася", UUID_A, "vasya", "pw")
    s = _secrets([c], with_reality=False)
    urls = build_subscription_for_client(s, c)
    assert len(urls) == 1
    assert urls[0].startswith("hysteria2://")


def test_subscription_disabled_client_empty() -> None:
    c = _client("Вася", UUID_A, "vasya", "pw", disabled=True)
    urls = build_subscription_for_client(_secrets([c]), c)
    assert urls == []


# ---------- full Xray client profile ----------


def test_xray_client_config_routes_ru_direct() -> None:
    client = _client("Вася", UUID_A, "vasya", "pw")
    config = build_xray_client_config(_secrets([client]), client)

    rules = config["routing"]["rules"]
    assert any(rule.get("domain") == ["geosite:category-ru"] for rule in rules)
    assert any(rule.get("ip") == ["geoip:ru"] for rule in rules)
    assert rules[-1]["outboundTag"] == "proxy"


def test_xray_client_config_custom_direct_domains() -> None:
    client = _client("Вася", UUID_A, "vasya", "pw")
    secrets = _secrets([client])
    secrets.routing = ClientRoutingConfig(
        ru_direct=False,
        private_direct=False,
        custom_direct_domains=["Bank.Example.RU.", "work.example.com"],
    )
    config = build_xray_client_config(secrets, client)
    rules = config["routing"]["rules"]

    assert rules[0]["domain"] == [
        "domain:bank.example.ru",
        "domain:work.example.com",
    ]
    assert all("geoip:ru" not in rule.get("ip", []) for rule in rules)


def test_xray_client_config_contains_no_private_key() -> None:
    client = _client("Вася", UUID_A, "vasya", "pw")
    config = build_xray_client_config(_secrets([client]), client)
    dumped = json.dumps(config)
    assert "PRIVATE_KEY_MUST_NOT_LEAK" not in dumped
    assert "PUBLIC_KEY_OK_TO_LEAK" in dumped
    reality = config["outbounds"][0]["streamSettings"]["realitySettings"]
    assert reality["password"] == "PUBLIC_KEY_OK_TO_LEAK"
    assert "publicKey" not in reality
    assert config["outbounds"][0]["streamSettings"]["network"] == "tcp"
    assert config["outbounds"][0]["streamSettings"]["tcpSettings"] == {
        "header": {"type": "none"}
    }
    assert config["outbounds"][0]["settings"]["vnext"][0]["users"][0]["flow"] == "xtls-rprx-vision"


# ---------- encode_subscription ----------


def test_encode_subscription_roundtrip() -> None:
    urls = ["vless://a@b:443?x=1#one", "hysteria2://c:d@e:443?y=2#two"]
    encoded = encode_subscription(urls)
    decoded = base64.b64decode(encoded).decode("utf-8")
    assert decoded == "\n".join(urls)


def test_encode_subscription_single() -> None:
    urls = ["vless://only"]
    encoded = encode_subscription(urls)
    assert base64.b64decode(encoded).decode("utf-8") == "vless://only"


def test_encode_subscription_empty() -> None:
    encoded = encode_subscription([])
    assert base64.b64decode(encoded).decode("utf-8") == ""


def test_encode_subscription_uses_standard_padding() -> None:
    # Standard base64, not urlsafe, and with '=' padding as needed.
    encoded = encode_subscription(["a" * 10])
    assert "=" in encoded or len(encoded) % 4 == 0
    base64.b64decode(encoded)  # must not raise


# ---------- build_clients_json ----------


def test_clients_json_structure() -> None:
    c = _client("Вася", UUID_A, "vasya", "pw", sub_token="t" * 32, client_id="cid-1")
    doc = build_clients_json(_secrets([c]))

    assert doc["version"] == 1
    assert doc["server"] == {"ip": "1.2.3.4", "domain": "node1.example.com"}
    assert doc["protocols"] == {"vless_reality": True, "hysteria2": True}
    assert doc["routing"]["ru_direct"] is True
    assert len(doc["clients"]) == 1

    entry = doc["clients"][0]
    assert entry["id"] == "cid-1"
    assert entry["label"] == "Вася"
    assert entry["sub_token"] == "t" * 32
    assert len(entry["urls"]) == 2
    assert entry["xray_config"]["routing"]["domainStrategy"] == "IPIfNonMatch"


def test_clients_json_excludes_disabled() -> None:
    a = _client("A", UUID_A, "a", "pw1", client_id="cid-a")
    b = _client("B", UUID_B, "b", "pw2", disabled=True, client_id="cid-b")
    doc = build_clients_json(_secrets([a, b]))
    ids = [c["id"] for c in doc["clients"]]
    assert ids == ["cid-a"]


def test_clients_json_empty_when_no_clients() -> None:
    doc = build_clients_json(_secrets([]))
    assert doc["clients"] == []


def test_clients_json_no_private_key_leak() -> None:
    c = _client("Вася", UUID_A, "vasya", "pw")
    dumped = dump_clients_json(_secrets([c]))
    assert "PRIVATE_KEY_MUST_NOT_LEAK" not in dumped
    assert "private_key" not in dumped


def test_clients_json_no_cloudflare_or_cert() -> None:
    c = _client("Вася", UUID_A, "vasya", "pw")
    doc = build_clients_json(_secrets([c]))
    assert "cloudflare" not in doc
    assert "cert" not in doc
    assert "openflux" not in doc


def test_clients_json_has_no_server_secrets() -> None:
    c = _client("Вася", UUID_A, "vasya", "pw")
    doc = build_clients_json(_secrets([c]))
    # top-level must only contain these keys
    assert set(doc.keys()) == {"version", "server", "protocols", "routing", "clients"}


def test_dump_clients_json_is_valid_json() -> None:
    c = _client("Вася", UUID_A, "vasya", "pw")
    dumped = dump_clients_json(_secrets([c]))
    parsed = json.loads(dumped)
    assert parsed["version"] == 1


def test_dump_clients_json_deterministic() -> None:
    c = _client("Вася", UUID_A, "vasya", "pw")
    s = _secrets([c])
    assert dump_clients_json(s) == dump_clients_json(s)


def test_dump_clients_json_preserves_unicode_labels() -> None:
    c = _client("Вася", UUID_A, "vasya", "pw")
    dumped = dump_clients_json(_secrets([c]))
    # ensure_ascii=False → cyrillic readable, not \uXXXX
    assert "Вася" in dumped


# ---------- golden: full document ----------


def test_golden_clients_json_single_client() -> None:
    c = _client(
        "Vasya",
        UUID_A,
        "vasya",
        "pw-secret",
        sub_token="f" * 32,
        client_id="cid-1",
    )
    doc = build_clients_json(_secrets([c]))

    assert doc == {
        "version": 1,
        "server": {"ip": "1.2.3.4", "domain": "node1.example.com"},
        "protocols": {"vless_reality": True, "hysteria2": True},
        "routing": {
            "ru_direct": True,
            "private_direct": True,
            "custom_direct_domains": [],
        },
        "clients": [
            {
                "id": "cid-1",
                "label": "Vasya",
                "sub_token": "f" * 32,
                "urls": [
                    build_vless_url(_secrets([c]), c),
                    build_hysteria_url(_secrets([c]), c),
                ],
                "xray_config": build_xray_client_config(_secrets([c]), c),
            }
        ],
    }


def test_golden_clients_json_no_domain_no_hysteria() -> None:
    c = _client("Vasya", UUID_A, "vasya", "pw")
    doc = build_clients_json(
        _secrets([c], domain=None, with_hysteria=False)
    )

    assert doc["server"] == {"ip": "1.2.3.4", "domain": None}
    assert doc["protocols"] == {"vless_reality": True, "hysteria2": False}
    assert len(doc["clients"][0]["urls"]) == 1
    assert doc["clients"][0]["urls"][0].startswith("vless://")
