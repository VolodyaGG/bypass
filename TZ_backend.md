# TZ_BACKEND.md — VPN-Forge Backend

## 0. Контекст

Локальное Python-приложение (FastAPI), которое одной кнопкой разворачивает
на чистом VPS (Ubuntu 22.04/24.04) VPN-комбайн через Ansible. Управление —
только с ПК пользователя. На VPS — «глухая» конфигурация: никаких веб-панелей,
только сервисы протоколов и микро-бэкенд подписок.

Данный TZ описывает **только бэкенд** (Python-модули, FastAPI-роуты,
Ansible-обвязка). UI (HTML/Tailwind) — отдельная итерация.

---

## 1. Поддерживаемые протоколы

Каждый протокол — опциональный, включается галочкой в UI.

| Протокол | Транспорт | Порт | Особенности |
|---|---|---|---|
| Hysteria 2 | UDP | 443 | Реальный LE-сертификат под `node1.<domain>`, `auth.type: userpass`, masquerade → apple.com |
| VLESS + XTLS-Reality + xHTTP | TCP | 443 | `dest: www.microsoft.com:443`, режим `packet-up`, per-user UUID |
| OpenFlux (exit-node) | TCP (исходящий) | — | Отдельное приложение, транспорт: `cupsonline` / `yandex` / `oneme`. Входящий порт не слушает |

Правила:
- Минимум один протокол должен быть включён.
- Если Hysteria 2 выключена → блок DNS/домен/серты в UI скрыт.
- Если включена — обязательны `fullchain.pem`, `privkey.pem` (загружаются файлами).
- 80/tcp зарезервирован под **sub-server** (микро-бэкенд подписок).

---

## 2. Модель данных (локальные секреты)

Файл: `data/secrets/<ip>.json`, права `600`, `.gitignore`.

```jsonc
{
  "version": 1,
  "ip": "1.2.3.4",
  "domain": "node1.example.com",
  "created_at": "2026-09-14T12:00:00Z",
  "updated_at": "2026-09-14T12:00:00Z",
  "protocols": {
    "hysteria2": true,
    "vless_reality": true,
    "openflux": false
  },
  "openflux": {
    "transport": "cupsonline",
    "yandex_url": null,
    "max_token": null,
    "max_uid": null,
    "encryption_key": null,
    "session_b64": null
  },
  "reality": {
    "private_key": "...",
    "public_key": "...",
    "short_id": "deadbeef",
    "dest": "www.microsoft.com:443",
    "server_name": "www.microsoft.com",
    "fingerprint": "chrome",
    "spider_x": "/",
    "xhttp_path": "/",
    "xhttp_mode": "packet-up"
  },
  "hysteria2": {
    "obfs_password": "...",
    "masquerade_url": "https://apple.com"
  },
  "clients": [
    {
      "id": "uuid-v4-внутренний",
      "label": "Вася",
      "created_at": "2026-09-14T12:00:00Z",
      "sub_token": "32-hex",
      "vless_uuid": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
      "hysteria_user": "vasya",
      "hysteria_pass": "base64-random-32",
      "disabled": false
    }
  ],
  "cloudflare": {
    "zone_id": "cached-after-first-lookup",
    "record_id": "dns-record-id"
  },
  "cert": {
    "not_after": "2026-12-13T00:00:00Z",
    "issuer": "Let's Encrypt",
    "sha256": "abcdef..."
  }
}
```

**Правила хранения:**
- UUID, Reality-ключи, Hysteria-пароли **никогда не перегенерируются** при повторном деплое — только читаются из файла.
- Принудительная ротация — только кнопкой «Перегенерировать всех» (аварийно).
- `sub_token` создаётся один раз при создании клиента, не меняется.

---

## 3. Структура проекта

```
vpnforge/
├── pyproject.toml
├── README.md
├── .gitignore
├── .env.example
├── vpnforge/
│   ├── __init__.py
│   ├── config.py
│   ├── models.py
│   ├── crypto_utils.py
│   ├── dns_manager.py
│   ├── secrets_store.py
│   ├── cert_validator.py
│   ├── client_manager.py
│   ├── config_builder.py
│   ├── sub_builder.py
│   ├── inventory_builder.py
│   ├── ansible_runner.py
│   ├── openflux_manager.py
│   ├── main.py
│   └── vps_sub_server/
│       ├── app.py
│       └── requirements.txt
├── ansible/
│   ├── ansible.cfg
│   ├── deploy.yml
│   ├── tasks/
│   │   ├── base.yml
│   │   ├── native.yml
│   │   ├── docker.yml
│   │   ├── hysteria.yml
│   │   ├── xray.yml
│   │   ├── openflux.yml
│   │   └── sub_server.yml
│   ├── templates/
│   │   ├── xray.json.j2
│   │   ├── hysteria.yaml.j2
│   │   ├── openflux.env.j2
│   │   ├── clients.json.j2
│   │   ├── sysctl-bbr.conf.j2
│   │   ├── vpnforge-xray.service.j2
│   │   ├── vpnforge-hysteria.service.j2
│   │   ├── vpnforge-openflux.service.j2
│   │   ├── vpnforge-sub.service.j2
│   │   └── docker-compose.yml.j2
│   └── group_vars/
│       └── all.yml.example
├── tests/
│   ├── conftest.py
│   ├── test_crypto_utils.py
│   ├── test_dns_manager.py
│   ├── test_secrets_store.py
│   ├── test_cert_validator.py
│   ├── test_client_manager.py
│   ├── test_config_builder.py
│   ├── test_sub_builder.py
│   ├── test_inventory_builder.py
│   ├── test_ansible_runner.py
│   ├── test_openflux_manager.py
│   └── test_main.py
└── data/
    └── secrets/
```

---

## 4. Модули — детально

### 4.1 `crypto_utils.py`

```python
def generate_uuid4() -> str: ...
def generate_x25519_keypair() -> tuple[str, str]: ...
def generate_short_id(length: int = 8) -> str: ...
def generate_password(length: int = 24) -> str: ...
def generate_sub_token() -> str: ...
def generate_obfs_password() -> str: ...
```

Требования:
- x25519 — через `cryptography.hazmat.primitives.asymmetric.x25519`.
- Кодировка ключей — base64url без padding.
- `short_id` — hex, чётной длины.
- Никаких `random.random()` — только `secrets`.

Тесты: длина, формат, уникальность, roundtrip.

### 4.2 `dns_manager.py`

```python
class CloudflareDNS:
    def __init__(self, api_token: str): ...
    def resolve_zone_id(self, root_domain: str) -> str: ...
    def upsert_a_record(self, zone_id: str, fqdn: str, ip: str,
                        ttl: int = 60, proxied: bool = False) -> str: ...
```

Требования:
- Endpoints: `GET /zones?name=`, `GET/POST/PUT /zones/<id>/dns_records`.
- Retry через `tenacity`.
- `proxied: false` принудительно, TTL = 60.
- Кастомные исключения: `CFAuthError`, `CFZoneNotFound`, `CFRecordError`.
- Маскировать токен в логах.

Тесты: `responses` для мока, create vs update, кэш zone_id.

### 4.3 `secrets_store.py`

```python
class SecretsStore:
    def __init__(self, root: Path): ...
    def exists(self, ip: str) -> bool: ...
    def load(self, ip: str) -> Secrets: ...
    def save(self, secrets: Secrets) -> None: ...
    def delete(self, ip: str) -> None: ...
    def archive(self, ip: str) -> Path: ...
    def export(self, ip: str) -> bytes: ...
    def import_(self, ip: str, raw: bytes) -> Secrets: ...
```

Требования:
- Atomic write через `tempfile` + `os.replace`.
- `chmod 600`.
- Валидация через Pydantic.
- Секреты не попадают в логи.

Тесты: roundtrip, права, атомарность, schema errors.

### 4.4 `cert_validator.py`

```python
class CertInfo(BaseModel):
    subject_cn: str
    san_domains: list[str]
    not_before: datetime
    not_after: datetime
    issuer_cn: str
    sha256: str

def parse_fullchain(path: Path) -> CertInfo: ...
def parse_privkey(path: Path) -> None: ...
def verify_pair(fullchain: Path, privkey: Path) -> bool: ...
def check_matches_domain(info: CertInfo, domain: str) -> bool: ...
```

Требования:
- Через `cryptography.x509`.
- Проверки: парсинг, матч ключа и серта, домен в CN/SAN, `not_after > now`.
- Понятные ошибки на русском.

Тесты: самоподписанные серты, негативные кейсы.

### 4.5 `client_manager.py`

```python
class ClientManager:
    def __init__(self, store: SecretsStore): ...
    def add_client(self, ip: str, label: str) -> Client: ...
    def remove_client(self, ip: str, client_id: str) -> None: ...
    def rename_client(self, ip: str, client_id: str, label: str) -> None: ...
    def disable_client(self, ip: str, client_id: str) -> None: ...
    def list_clients(self, ip: str) -> list[Client]: ...
    def rotate_all(self, ip: str) -> None: ...
```

Правила:
- `sub_token`, `vless_uuid`, `hysteria_user/pass` создаются один раз.
- `label` уникален.
- `disabled=True` → исключается из конфигов и подписки.
- `rotate_all` архивирует текущие секреты.

Тесты: CRUD, конфликты, сохранение UUID, disabled не попадает.

### 4.6 `config_builder.py`

```python
def build_xray_config(secrets: Secrets) -> dict: ...
def build_hysteria_config(secrets: Secrets) -> dict: ...
```

Xray: VLESS Reality xhttp 443/tcp, `network: xhttp`, `security: reality`, `mode: packet-up`, без api-инбаунда.

Hysteria 2: `listen: :443`, tls.cert/key, `auth.type: userpass`, masquerade → apple.com, obfs salamander (опц.).

Тесты: golden-файлы, disabled не попадают, валидность JSON/YAML.

### 4.7 `sub_builder.py`

```python
def build_clients_json(secrets: Secrets) -> dict: ...
def build_vless_url(secrets: Secrets, client: Client) -> str: ...
def build_hysteria_url(secrets: Secrets, client: Client) -> str: ...
def encode_subscription(urls: list[str]) -> str: ...
```

VLESS URL:
```
vless://<uuid>@<host>:443?type=xhttp&security=reality&pbk=<pbk>&fp=chrome&sni=<sni>&sid=<sid>&spx=%2F&path=%2F&mode=packet-up#<label>
```

Hysteria URL:
```
hysteria2://<user>:<pass>@<domain>:443?sni=<domain>&insecure=0&obfs=salamander&obfs-password=<obfs>#<label>
```

`clients.json` — структура для `vps_sub_server/app.py` (server, protocols, reality, hysteria2, clients).

Тесты: формат URL, base64 roundtrip, disabled, fallback на IP без домена.

### 4.8 `inventory_builder.py`

```python
def build_hosts_ini(vps: VPSConnection) -> str: ...
def build_group_vars(secrets: Secrets, cert: CertInfo, clients_json: dict) -> dict: ...
```

- `hosts.ini` — `[vpn]` с `ansible_user`, `ansible_port`, `ansible_ssh_private_key_file`.
- Пароль — только через `--extra-vars`, не в файл.
- `group_vars/all.yml` — runtime, секреты, конфиги, base64 PEM, openflux env.

Тесты: снапшоты, отсутствие секретов в `hosts.ini`.

### 4.9 `ansible_runner.py`

```python
class AnsibleRunner:
    def __init__(self, project_root: Path, ansible_bin: str = "ansible-playbook"): ...
    async def run(self, playbook: Path, inventory: Path,
                  extra_vars: dict | None = None,
                  extra_vars_file: Path | None = None) -> AsyncIterator[str]: ...
```

- `subprocess.Popen`, `stdout=PIPE`, `stderr=STDOUT`.
- Env: `ANSIBLE_FORCE_COLOR=0`, `ANSIBLE_NOCOLOR=1`, `PYTHONUNBUFFERED=1`.
- Построчный yield.
- Таймаут 30 мин + kill.
- Exit code через `.wait()`.

Тесты: фейковый скрипт, стрим, таймаут, exit code.

### 4.10 `openflux_manager.py`

```python
async def run_openflux_deploy(runner: AnsibleRunner, ...) -> str: ...
def parse_session_b64(log_output: str) -> str: ...
```

- Парсинг `COPY THIS TO CLIENT` из `journalctl`/`docker logs`.
- Retry 5×3 сек.
- Сохранение `session_b64` в secrets.

Тесты: парсинг (негативные кейсы), retry.

### 4.11 `main.py` (FastAPI, без UI)

| Метод | Путь | Назначение |
|---|---|---|
| GET | `/api/health` | healthcheck |
| POST | `/api/cert/validate` | 2 файла → `CertInfo` |
| POST | `/api/dns/upsert` | ручной апсерт A-записи |
| POST | `/api/secrets/load` | загрузка secrets для IP |
| POST | `/api/secrets/export` | скачать secrets.json |
| POST | `/api/secrets/import` | загрузить secrets.json |
| GET | `/api/clients?ip=...` | список клиентов |
| POST | `/api/clients` | добавить |
| PATCH | `/api/clients/{id}` | rename/disable |
| DELETE | `/api/clients/{id}` | удалить |
| POST | `/api/clients/rotate` | ротация всех |
| POST | `/api/deploy` | запуск, SSE-стрим |
| GET | `/api/deploy/stream/{job_id}` | SSE-подписка |
| GET | `/api/sub/{sub_token}` | локальный прокси к sub-server (опц.) |

- Pydantic для request/response.
- Ошибки: `{"error": {"code": "...", "message": "..."}}`.
- SSE через `sse-starlette`.
- Без прямого ФС-доступа в роутах.
- Логи без секретов.

Тесты: `httpx.AsyncClient` + `ASGITransport`.

### 4.12 `vps_sub_server/app.py`

```python
from fastapi import FastAPI, HTTPException
from fastapi.responses import PlainTextResponse
import json, base64, pathlib

app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
CLIENTS_FILE = pathlib.Path("/opt/vpnforge/sub/clients.json")

@app.get("/sub/{token}", response_class=PlainTextResponse)
def get_sub(token: str) -> str: ...

@app.get("/health")
def health() -> dict: ...
```

- Перечитывает файл на каждый запрос.
- `text/plain` с base64.
- 404 при отсутствии токена.
- Слушает `0.0.0.0:80`.
- systemd, `Restart=always`.

Тесты: `httpx.ASGITransport`, найден/не найден, content-type.

---

## 5. Ansible — обвязка

### 5.1 `deploy.yml`

Порядок:
1. `base` — apt, sysctl (BBR + fq), ufw/fail2ban (опц.).
2. Ветвление по `runtime`: `native.yml` / `docker.yml`.
3. `hysteria.yml`.
4. `xray.yml`.
5. `openflux.yml` (если включён).
6. `sub_server.yml` — venv + pip + systemd.
7. `verify.yml` — is-active / compose ps.

### 5.2 Идемпотентность

- Все таски идемпотентны.
- Handlers на рестарт при изменении конфигов.
- При изменении клиентов — `restart xray` + `reload hysteria`.

### 5.3 Секреты

- `group_vars/all.yml` в plain, удаляется после запуска.
- `data/runs/<job_id>/` — временная папка, чистится.
- `no_log: true` на чувствительных тасках.

---

## 6. Поток выполнения

```
UI → POST /api/deploy (DeployRequest)
       ├─ 1. validate cert
       ├─ 2. Cloudflare upsert A
       ├─ 3. secrets_store.load или создать
       ├─ 4. crypto_utils генерит Reality + Hysteria
       ├─ 5. client_manager: дефолтный "default" если пусто
       ├─ 6. config_builder → xray.json, hysteria.yaml
       ├─ 7. sub_builder → clients.json
       ├─ 8. inventory_builder → hosts.ini + group_vars/all.yml
       ├─ 9. ansible_runner.run(deploy.yml) → SSE
       ├─10. openflux_manager парсит base64
       ├─11. secrets_store.save
       └─12. return job_id + статус
```

---

## 7. Зависимости (Poetry)

```toml
[tool.poetry.dependencies]
python = "^3.11"
fastapi = "^0.115"
uvicorn = {extras = ["standard"], version = "^0.32"}
jinja2 = "^3.1"
pyyaml = "^6.0"
requests = "^2.32"
tenacity = "^9.0"
pydantic = "^2.9"
pydantic-settings = "^2.6"
cryptography = "^43.0"
python-multipart = "^0.0.12"
sse-starlette = "^2.1"

[tool.poetry.group.dev.dependencies]
pytest = "^8.3"
pytest-asyncio = "^0.24"
httpx = "^0.27"
responses = "^0.25"
freezegun = "^1.5"
ruff = "^0.7"
mypy = "^1.13"
```

Ansible — системно (`pipx` / `apt`), не через Poetry.

---

## 8. Тесты

- Каждый модуль — свой `test_*.py`.
- Покрытие ≥85%.
- Без сетевых вызовов (`responses`, mock).
- `tmp_path` для ФС.
- `freezegun` для дат.
- FastAPI — `httpx.AsyncClient` + `ASGITransport`.

---

## 9. Что НЕ делаем в этой итерации

- UI (HTML/Tailwind).
- gRPC API Xray — рестарт.
- QR-коды.
- Автообновление подписки на клиенте.
- ACME на сервере — серты грузятся файлами.
- StatsService.
- Мультисерверность.
- OpenFlux в sing-box.
- Windows-специфика ansible-runner.

---

## 10. Критерии готовности

1. `poetry install && poetry run pytest` — зелёные, покрытие ≥85%.
2. `poetry run ruff check` — чисто.
3. `poetry run mypy vpnforge` — чисто (strict).
4. `uvicorn vpnforge.main:app` — поднимается, `/api/health` отвечает.
5. E2E (manual): валидный cert + CF-токен + чистый VPS → деплой → `curl http://<vps>/sub/<token>` отдаёт base64.
6. Секреты на диске — только `data/secrets/<ip>.json` (600).
7. README описывает установку, env, тесты, ограничения.
