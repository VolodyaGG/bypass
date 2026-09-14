# VPN-Forge

VPN-Forge — это локальный control plane для развёртывания VPN-стека на чистом Ubuntu VPS через Ansible. Проект объединяет несколько протоколов: Hysteria 2, VLESS Reality xHTTP и OpenFlux, а также умеет управлять клиентами, генерировать подписки и деплоить сервисы на удалённый сервер.

Основная идея простая: вся логика управления остаётся на вашей машине, а на VPS запускаются только нужные сервисы и небольшой subscription-server.

## Что умеет проект

- валидировать TLS-сертификаты;
- поднимать DNS A-запись через Cloudflare;
- хранить секреты по VPS-адресу;
- создавать и управлять клиентами;
- генерировать subscription URLs;
- запускать деплой через Ansible;
- отслеживать прогресс деплоя в realtime через SSE;
- поддерживать OpenFlux как один из протоколов туннеля.

## Архитектура

- backend: FastAPI, Python
- frontend: статический UI, отдаётся через FastAPI
- orchestration: Ansible для VPS
- storage: JSON-файлы в `data/secrets/`
- target server: Ubuntu VPS, где запускаются xray/hysteria/openflux/subscription сервисы

Ключевой модуль: `vpnforge/main.py`.
Ключевая логика OpenFlux: `vpnforge/openflux_manager.py`.
Ansible-плейбук деплоя: `ansible/deploy.yml`.

## Требования

Перед запуском убедитесь, что установлено:

- Python 3.11+
- [Poetry](https://python-poetry.org/)
- Ansible (`ansible-playbook` должен быть в `PATH`)
- SSH-доступ к целевому VPS (ключ или пароль)
- Для DNS/Cloudflare: Cloudflare API token (опционально)

Для установки Ansible можно использовать, например:

```bash
pipx install ansible-core
```

## Установка зависимостей

```bash
cd <путь_к_проекту>
poetry install
```

Если проект использует переменные окружения, создайте `.env` или задайте нужные значения в shell. В проекте есть параметры, которые читаются через `pydantic-settings`, а также поддерживаются переменные с префиксом `VPNFORGE_`.

Типичные переменные:

- `VPNFORGE_DATA_DIR` — каталог для секретов и run-данных
- `VPNFORGE_LOG_LEVEL` — уровень логирования
- `VPNFORGE_ANSIBLE_BIN` — путь к `ansible-playbook`
- `VPNFORGE_ANSIBLE_TIMEOUT` — таймаут деплоя
- `VPNFORGE_CF_API_TOKEN` — токен Cloudflare для DNS

## Запуск проекта

### Запуск backend

```bash
cd <путь_к_проекту>
poetry run uvicorn vpnforge.main:app --host 127.0.0.1 --port 8000
```

После этого приложение будет доступно по адресу:

- UI: http://127.0.0.1:8000/
- health check: http://127.0.0.1:8000/api/health

### Проверка

```bash
curl http://127.0.0.1:8000/api/health
```

Ожидаемый ответ:

```json
{"status":"ok"}
```

## Базовые API-эндпоинты

- `GET /api/health` — статус сервера
- `POST /api/cert/validate` — валидация сертификата
- `POST /api/dns/upsert` — создание/обновление DNS A-записи
- `POST /api/secrets/load` — загрузка secrets по IP
- `POST /api/secrets/export` — экспорт secrets
- `POST /api/secrets/import` — импорт secrets
- `GET /api/clients` — список клиентов
- `POST /api/clients` — добавление клиента
- `PATCH /api/clients/{id}` — обновление клиента
- `DELETE /api/clients/{id}` — удаление клиента
- `POST /api/deploy` — запуск деплоя
- `GET /api/deploy/stream/{job_id}` — SSE-поток логов деплоя
- `GET /api/sub/{token}` — локальная подписка для клиента

## OpenFlux

Проект уже содержит реальную интеграцию с upstream-репозиторием OpenFlux:

- https://github.com/p1neappleXpress/OpenFlux

Что здесь реализовано:

- модель конфигурации OpenFlux в `vpnforge/models.py`;
- генерация аргументов запуска `universal-bypass-tool` в `vpnforge/openflux_manager.py`;
- Ansible-задача для сборки и запуска OpenFlux на VPS в `ansible/tasks/openflux.yml`;
- UI-поля для выбора транспорта и режима в `vpnforge/web/templates/index.html`;
- данные для деплоя отправляются через backend в `POST /api/deploy`.

Поддерживаемые транспорты в проекте:

- `cupsonline`
- `yandex`
- `oneme`

Режимы:

- `proxy` — безопасный и рекомендуемый режим
- `raw` — Linux-only, требует root и сетевые/iptables настройки

### Важные ограничения OpenFlux в этом проекте

- `raw` mode не настраивает iptables автоматически;
- Docker runtime не поддерживается в текущей реализации;
- часть сценариев зависит от того, как именно устроен upstream OpenFlux и какие возможности доступны в его документации;
- для реального деплоя нужен живой VPS и корректная SSH-среда.

Это нормально для MVP/alpha-версии, но означает, что проект пока не является полностью универсальной production-ready реализацией всех режимов OpenFlux.

## Запуск тестов

```bash
cd <путь_к_проекту>
poetry run pytest
```

Также можно запускать linters:

```bash
poetry run ruff check
poetry run mypy vpnforge
```

## Ограничения текущей версии

- нет полноценной авторизации/ролей;
- проект рассчитан на локальный control plane и на доверенную среду;
- сертификаты передаются в деплой вручную, а не автоматически выдаются на VPS;
- no UI/UX hardening, no multi-server orchestration;
- OpenFlux raw mode и часть edge cases требуют ручной настройки на сервере;
- для реального production deployment нужна отдельная проверка окружения и сетевой безопасности.

## Рекомендуемый сценарий использования

1. Подготовить VPS и SSH-доступ.
2. Установить зависимости через Poetry.
3. Запустить backend локально.
4. Открыть UI по адресу `http://127.0.0.1:8000/`.
5. Настроить VPS, домен, TLS, протоколы и OpenFlux параметры.
6. Нажать deploy и следить за логами.
7. После завершения проверить подписки и доступность сервисов на VPS.

## Краткий вывод

VPN-Forge — это проект-оркестратор для VPN-стека, который уже умеет многое: деплои, кейсы с OpenFlux, управление секретами, составление подписок и работа с сервером через Ansible. Он находится в стадии зрелого MVP, но всё ещё требует аккуратной настройки окружения и проверки реального VPS-репозитория перед production-использованием.
