# Hysteria 2 — nider с публичным TLS

Адрес: `103.118.208.229:24443`, транспорт UDP, Hysteria 2 версии 2.13.0.
Имя для TLS (SNI): `yaposo.su`. Сертификат Let’s Encrypt с `ger`, действует
до 3 января 2027 года, 18:39:46 UTC (21:39:46 по Москве).

## Подключение

Импортировать полную строку из `import-uri.txt` в приложение с поддержкой Hysteria 2.
Проверка TLS включена: `insecure=0`. Отдельный CA-файл и отпечаток не нужны.
Адрес сервера должен оставаться IP `103.118.208.229`, SNI — `yaposo.su`.
DNS домена не изменён; доменное имя здесь используется для проверки сертификата.
Старый импорт с `node.yaposo.su` необходимо заменить новым.

Официальный клиент из этой папки:

```sh
hysteria client -c client.yaml
```

Локальный SOCKS5: `127.0.0.1:10808`.
`client.yaml`, `import-uri.txt` и `secrets.yml` содержат доступ к прокси;
не публиковать и не добавлять в репозиторий.
Приватного TLS-ключа в этом комплекте нет.

## Развёртывание и продление

```sh
ansible-playbook deploy.yml
```

Playbook проверяет доверенную цепочку, имя yaposo.su, срок не менее 7 дней,
соответствие ключа сертификату на ger; затем копирует fullchain и ключ на nider
через SSH и Ansible, не сохраняя ключ в постоянные локальные файлы.
Сертификат и ключ на nider доступны root и выделенной группе hysteria-nider.
Предыдущая пара сохранена штатными backup-файлами Ansible на nider.
Перезапускается только hysteria2-nider при изменениях.
`deploy-public-tls.yml` — идентичный playbook с явным названием для публичного TLS.

На ger уже включён certbot.timer. Автоматическая доставка продлённых сертификатов
с ger на nider пока не настроена. После продления на ger повторить deploy.yml,
обязательно до истечения установленного сертификата на nider.

## Управление

```sh
ssh nider 'systemctl status hysteria2-nider --no-pager'
ssh nider 'journalctl -u hysteria2-nider -n 50 --no-pager'
ansible-playbook stop.yml
```

stop.yml только останавливает и отключает наш сервис, сохраняя конфигурацию.
Для возобновления выполнить deploy.yml.

Файлы сервера: `/etc/hysteria2-nider/`, `/usr/local/lib/hysteria2-nider/`,
`/etc/systemd/system/hysteria2-nider.service`. Выделенный пользователь hysteria-nider.
DNS, SSH, firewall, sysctl и сервисы на ger не изменялись.
Общий исходный VPN-Forge playbook не запускался, существующие изменения проекта сохранены.

UDP 443 давал тайм-аут с этого компьютера; UDP 24443 проверен реальным HTTPS-запросом
через Hysteria с выходным IP 103.118.208.229. Точная причина недоступности UDP 443
на маршруте не установлена.

`verification.json` — проверка с этого компьютера с системным хранилищем доверия,
включая отказ при неверном пароле и неверном имени TLS.

Документация: [клиент](https://v2.hysteria.network/docs/advanced/Full-Client-Config/),
[ссылки импорта](https://v2.hysteria.network/docs/developers/URI-Scheme/).

## Пользователь juuul

Добавлен 13 ноября 2026 года. Профиль `juuul-client.yaml`, ссылка `juuul-import-uri.txt`.
Отдельный случайный пароль в `hy_users.juuul` файла secrets.yml; не публиковать.
TLS и obfs сохраняются, новый auth имеет вид `juuul:пароль`.

Для сохранения совместимости со старым общим паролем используется штатный механизм
command auth Hysteria. Команда `/usr/local/lib/hysteria2-nider/authenticate` сравнивает
SHA256 предоставленных данных с `/etc/hysteria2-nider/auth-users.json` и возвращает
имя пользователя. Старые подключения имеют имя `legacy`, новые — `juuul`.
В реестре сервера хранятся хеши случайных секретов. Старый профиль продолжает работать.

Обновить пользователей без обращения к сертификатам на ger:
`ansible-playbook update-users.yml`.
Полный deploy.yml также устанавливает актуальную авторизацию.
Результаты проверки обоих пользователей: users-verification.json.
