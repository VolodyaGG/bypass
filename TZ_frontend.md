# TZ_FRONTEND.md — bypass Frontend

## 0. Контекст

Фронтенд — **одностраничное веб-приложение** (SPA в одном `index.html` + Tailwind + vanilla JS), которое обслуживается тем же FastAPI-сервером, что и бэкенд. Работает **локально на ПК пользователя** (`http://127.0.0.1:8000`).

Цель UI — **терминальная сессия в стиле JARVIS / Tony Stark**, где пользователь **нелинейно** заполняет поля, запускает деплой и наблюдает за статусом плейбуков во **всплывающем overlay**, который можно закрыть и продолжить работу с формой.

Ключевая идея: **не bash-скрипт, не wizard сверху вниз, а единое интерактивное полотно**, где любое поле доступно в любой момент, а действие — это `[▸ DEPLOY]` внизу.

---

## 1. Визуальная концепция: «Stark Terminal»

Гибрид терминала и голографической панели JARVIS. Моноширинный шрифт везде, тёмный фон, синие акценты, glow, тонкие рамки, JARVIS-анимации.

### 1.1 Палитра (dark, blue)

| Токен | HEX | Где используется |
|---|---|---|
| `bg-base` | `#0A0E1A` | основной фон |
| `bg-panel` | `#0F1626` | панели, карточки |
| `bg-elevated` | `#16203A` | overlay, модалки |
| `bg-terminal` | `#05080F` | фон терминала логов (глубже) |
| `border-subtle` | `#1F2A44` | границы панелей |
| `border-glow` | `#2E4A7A` | границы при hover/focus |
| `accent` | `#3B82F6` | главный синий акцент |
| `accent-bright` | `#60A5FA` | яркий акцент |
| `accent-glow` | `#93C5FD` | свечение, блики |
| `text` | `#E5E7EB` | основной текст |
| `text-muted` | `#94A3B8` | подписи, hint |
| `text-dim` | `#64748B` | декоративный текст |
| `success` | `#10B981` | ok, active |
| `warning` | `#F59E0B` | warning |
| `error` | `#EF4444` | error, failed |

**Glow:** `box-shadow: 0 0 20px rgba(59,130,246,0.25)` на активных/focus-элементах.

### 1.2 Шрифт

- **Всё — JetBrains Mono** (Google Fonts, веса 300/400/500/700).
- Fallback: `ui-monospace, SFMono-Regular, Menlo, monospace`.
- Никаких пропорциональных шрифтов.

```html
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@300;400;500;700&display=swap" rel="stylesheet">
```

### 1.3 Анимации (JARVIS-style)

| Событие | Анимация | Длительность |
|---|---|---|
| Появление секции | fade + slide-up | 180ms ease-out |
| Открытие overlay | slide-up + fade + blur фона | 250ms ease-out |
| Hover кнопки | glow pulse | 200ms |
| Spinner загрузки | SVG кольца-сканер | 1.5s loop |
| Активный статус | пульсация точки `◉` | 2s infinite |
| Успех деплоя | flash зелёного свечения по краям | 1s |
| Лог-строка | fade-in | 50ms |
| Focus на инпуте | glow границы | 150ms |

---

## 2. Layout — единый экран

Одна страница, вертикальный поток, `max-w-5xl` по центру. Секции-панели появляются/скрываются условно.

```
╔══════════════════════════════════════════════════════════════╗
║  🔨 bypass v0.1.0                    [◉ status]  [⌘ help] ║
╠══════════════════════════════════════════════════════════════╣
║                                                              ║
║  ┌─ ▸ PROTOCOLS ─────────────────────────────────────────┐   ║
║  │  ◉ Hysteria 2          UDP/443, real TLS              │   ║
║  │  ◉ VLESS Reality       TCP/443, xHTTP packet-up       │   ║
║  │  ◯ OpenFlux            separate client, tunnel        │   ║
║  └───────────────────────────────────────────────────────┘   ║
║                                                              ║
║  ┌─ ▸ VPS ───────────────────────────────────────────────┐   ║
║  │  IP        > 1.2.3.4___________________               │   ║
║  │  Port      > 22                                       │   ║
║  │  User      > root                                     │   ║
║  │  Auth      ◉ SSH key    ◯ Password                    │   ║
║  │  Key path  > ~/.ssh/id_ed25519________________        │   ║
║  │  Runtime   ◉ native     ◯ docker                      │   ║
║  └───────────────────────────────────────────────────────┘   ║
║                                                              ║
║  ┌─ ▸ DNS & CERTS ───────────────────────────────────────┐   ║
║  │  CF Token  > **************************  [👁]        │   ║
║  │  Root      > example.com                              │   ║
║  │  Sub       > node1                                    │   ║
║  │  Cert      > [ select fullchain.pem ]  ✓ OK           │   ║
║  │  Key       > [ select privkey.pem   ]                 │   ║
║  └───────────────────────────────────────────────────────┘   ║
║                                                              ║
║  ┌─ ▸ OPENFLUX ──────────────────────────────────────────┐   ║
║  │  Transport  ◯ cupsonline  ◯ yandex  ◯ oneme           │   ║
║  │  (поля транспорта появляются ниже)                    │   ║
║  └───────────────────────────────────────────────────────┘   ║
║                                                              ║
║  ┌─ ▸ CLIENTS ───────────────────────────────────────────┐   ║
║  │  > Vasya    VLESS+Hy2   /sub/7f3a…  [⎘] [✎] [❌]      │   ║
║  │  > Petya    VLESS+Hy2   /sub/9d4e…  [⎘] [✎] [❌]      │   ║
║  │  [ + add client ]                                     │   ║
║  └───────────────────────────────────────────────────────┘   ║
║                                                              ║
║  ┌─ ▸ SERVICES ──────────────────────────────────────────┐   ║
║  │  ● xray.service          active                       │   ║
║  │  ● hysteria.service      active                       │   ║
║  │  ● vpnforge-sub.service  active                       │   ║
║  └───────────────────────────────────────────────────────┘   ║
║                                                              ║
╠══════════════════════════════════════════════════════════════╣
║  bypass > _                                      [▸ DEPLOY]    ║
╚══════════════════════════════════════════════════════════════╝
```

### 2.1 Правила появления секций

| Секция | Когда показывается |
|---|---|
| PROTOCOLS | всегда |
| VPS | всегда |
| DNS & CERTS | только если `Hysteria 2` включена |
| OPENFLUX | только если `OpenFlux` включён |
| CLIENTS | только после успешного деплоя + если включён VLESS или Hysteria 2 |
| SERVICES | только после успешного деплоя |
| Нижняя панель `bypass >` | всегда (задел под CLI) |

### 2.2 Нелинейность

- Все секции на одном полотне, скролл вертикальный.
- Любое поле доступно в любой момент, никаких «вперёд/назад».
- Изменение галочки протокола мгновенно скрывает/показывает зависимые секции.
- Значения не сбрасываются при скрытии/показе.

---

## 3. Компоненты в терминальном стиле

### 3.1 Radio

```
◉ Hysteria 2         UDP/443, real TLS
◯ VLESS Reality      TCP/443, xHTTP packet-up
```

- Клик мышью или `←/→` в фокусе.
- Метка `◉` — accent-bright + glow.
- Метка `◯` — text-dim.
- Лейбл в фокусе — accent.

### 3.2 Checkbox

```
◉ Hysteria 2
◯ OpenFlux
```

- Визуально как radio, но независимый.
- `Space` переключает в фокусе.
- Используется только в секции PROTOCOLS.

### 3.3 Input

```
IP      > 1.2.3.4___________________
```

- Слева — лейбл (`text-muted`), выровнен по ширине.
- Справа — `>` + инпут.
- Инпут: прозрачный фон, нижняя граница `border-subtle`, при focus — `border-glow` + glow.
- Placeholder — `text-dim`.

### 3.4 Password input

```
CF Token  > **************************  [👁]
```

- `type="password"`, кнопка `[👁]` — toggle показать.
- В фокусе — glow.

### 3.5 File input (для PEM)

```
Cert  > [ select fullchain.pem ]  ✓ OK
Key   > [ select privkey.pem   ]
```

- Кнопка `[ select ]` открывает file-picker.
- После выбора — имя файла + inline-статус (`✓ OK` / `✗ error`).
- Валидация серта — отдельной кнопкой `[ ✓ validate ]` рядом с Key.

### 3.6 Button

- Основная: `[▸ DEPLOY]` — крупная, accent, glow на hover.
- Вторичные: `[ + add client ]`, `[⎘ copy]`, `[✎ rename]`, `[❌ delete]` — маленькие, `border-subtle`, hover → `border-glow`.
- При загрузке — спиннер-сканер + disable.

### 3.7 Spinner (JARVIS-сканер)

Вместо кружка — SVG с 2-3 вращающимися кольцами разного радиуса и opacity. Размер — 16/24/32px.

### 3.8 Status dot

- `●` active — `success` + медленная пульсация.
- `●` failed — `error`, без пульсации.
- `●` unknown — `text-dim`.

### 3.9 Terminal (в overlay)

- Фон `bg-terminal`, monospace, `text-xs`.
- Каждая строка — `<div class="log-line">`.
- Цвета:
  - `ok:` / `changed:` → success
  - `fatal:` / `ERROR` → error
  - `warning:` / `WARN` → warning
  - обычное → `text-muted`
- Автоскролл вниз (тумблер в углу).
- Появление строки — fade-in 50ms.

---

## 4. Overlay статуса деплоя

Открывается при нажатии `[▸ DEPLOY]` или иконки `[◉ status]` в хедере.

```
╔══════════════════════════════════════════════════════════════╗
║  ▸ DEPLOYMENT                                 [×] [⎘] [⇩]   ║
╠══════════════════════════════════════════════════════════════╣
║  ▸ apt ✓  ▸ runtime ◐  ▸ xray ○  ▸ hysteria ○  ▸ sub ○     ║
╠══════════════════════════════════════════════════════════════╣
║  $ ansible-playbook -i hosts.ini deploy.yml                  ║
║  PLAY [bypass deploy] ***                                 ║
║  TASK [base : apt update] ***                                ║
║  ok: [1.2.3.4]                                               ║
║  TASK [base : install docker] ***                            ║
║  changed: [1.2.3.4]                                          ║
║  ...                                                         ║
║                                                              ║
║                                                              ║
╠══════════════════════════════════════════════════════════════╣
║  [ ▸ cancel ]                                                ║
╚══════════════════════════════════════════════════════════════╝
```

### Поведение

- Выезжает снизу вверх (slide-up), фон страницы затемняется + blur.
- **Закрывается `[×]` или `Esc`.** Поля под overlay остаются доступны после закрытия.
- **Логи стримятся в фоне** через SSE, даже если overlay закрыт. Индикатор `[◉ status]` в хедере **пульсирует синим**, пока деплой активен.
- Повторное открытие `[◉ status]` — overlay с текущими логами.
- **`[⎘]`** — копировать весь лог в буфер.
- **`[⇩]`** — скачать `.log`.
- **`[▸ cancel ]`** — `POST /api/deploy/cancel/<job_id>`, прерывает SSE, kill Ansible.
- При завершении деплоя overlay **автоматически открывается** с финальным статусом:
  - `✓ Deployment complete.` + зелёный flash + появляются секции CLIENTS и SERVICES.
  - `✗ Deploy failed: <reason>` + красный border + inline-подсказка.

### Прогресс-бар этапов

Сверху overlay — 6 этапов:
```
▸ apt  ▸ runtime  ▸ xray  ▸ hysteria  ▸ sub  ▸ verify
```
Каждый этап:
- `○` — pending (text-dim)
- `◐` — running (accent, пульсация)
- `✓` — done (success)
- `✗` — failed (error)

Этапы определяются на бэкенде и отдаются в SSE-событиях `stage`.

---

## 5. Секция CLIENTS

Появляется после успешного деплоя, если включён VLESS Reality или Hysteria 2.

```
┌─ ▸ CLIENTS ──────────────────────────────────────────────┐
│  > Vasya    VLESS+Hy2   /sub/7f3a…   [⎘] [✎] [❌]        │
│  > Petya    VLESS+Hy2   /sub/9d4e…   [⎘] [✎] [❌]        │
│  [ + add client ]                                        │
└──────────────────────────────────────────────────────────┘
```

### Действия

- **`[ + add client ]`** — открывает модалку `Add client`, поле `Label`, кнопки `[ ▸ add ]` / `[ cancel ]`.
- **`[⎘]`** — копировать sub URL в буфер + toast `Copied.`.
- **`[✎]`** — переименовать (модалка с инпутом).
- **`[❌]`** — удалить (модалка подтверждения).
- Строка клиента показывает: `label`, включённые протоколы (сокращённо `VLESS+Hy2`), `sub_token` (первые 8 символов + `…`).

### Просмотр конфига

Клик по строке (или отдельная кнопка) открывает модалку с plain-text:
```
vless://<uuid>@<host>:443?type=xhttp&...
hysteria2://<user>:<pass>@<domain>:443?...
```
Кнопка `[⎘ copy]`.

⚠️ **QR-кодов нет** — по решению.

---

## 6. Секция SERVICES

Появляется после успешного деплоя.

```
┌─ ▸ SERVICES ─────────────────────────────────────────────┐
│  ● xray.service          active                          │
│  ● hysteria.service      active                          │
│  ● vpnforge-sub.service  active                          │
│  ● openflux.service      active                          │
└──────────────────────────────────────────────────────────┘
```

- Polling `GET /api/services/status?ip=...` каждые 5s.
- Точка `●` — `success` + пульсация при active, `error` при failed, `text-dim` при unknown.
- Имя сервиса — `text`.
- Статус — `text-muted`.

⚠️ **Доп. требование к бэкенду:** роут `/api/services/status`.

---

## 7. Нижняя панель `bypass >`

```
bypass > _                                      [▸ DEPLOY]
```

- Слева — декоративная псевдо-команда с мигающим курсором (`_`).
- Справа — главная кнопка `[▸ DEPLOY]` (запускает деплой).
- **Задел под CLI:** в будущем сюда можно вводить команды `/set ip 1.2.3.4`, `/deploy`, `/status` и т.п. В этой итерации — **декоративная, не реагирует на ввод**.

---

## 8. Технологии

| Слой | Технология |
|---|---|
| Разметка | HTML5 + Jinja2 (`index.html`) |
| Стили | Tailwind CSS CDN `3.4.16` + `style.css` для кастомных анимаций |
| Логика | Vanilla JS, ES2022, один `app.js` |
| Иконки | Lucide CDN `0.469.0` |
| Шрифт | JetBrains Mono (Google Fonts) |
| Стрим | SSE (`EventSource`) |
| HTTP | `fetch` + `async/await` |
| Состояние | Простой объект `state` + `render()` |
| Персистентность UI | `localStorage` (включая секреты — приложение локальное) |

**Никаких сборщиков.** Статика отдаётся через `StaticFiles` + Jinja2-шаблон.

**Оффлайн-fallback (в README):** как положить Tailwind/Lucide/JetBrains в `static/vendor/`.

---

## 9. Структура файлов

```
vpnforge/
├── web/
│   ├── templates/
│   │   └── index.html
│   └── static/
│       ├── app.js
│       ├── style.css
│       └── favicon.svg
```

FastAPI отдаёт:
- `GET /` → `index.html` (Jinja2).
- `GET /static/*` → `StaticFiles(directory="web/static")`.

---

## 10. Состояние UI

```js
const state = {
  protocols: { hysteria2: false, vless_reality: false, openflux: false },
  vps: { ip: '', port: 22, user: 'root', auth: 'key', keyPath: '', password: '', runtime: 'native' },
  dns: { cfToken: '', root: '', sub: '' },
  certs: { fullchainPath: '', privkeyPath: '', info: null },
  openflux: { transport: null, yandexUrl: '', maxToken: '', maxUid: '', encKey: '' },
  deploy: { jobId: null, running: false, stages: {} },
  clients: [],
  services: {},
  theme: 'dark',
};
```

- **Секретные поля** (cfToken, sshPassword, пути к PEM) — **сохраняются в localStorage** (приложение локальное).
- **Не-секретные** — тоже в localStorage.
- `render()` — точечно обновляет DOM без фреймворка.

---

## 11. SSE

```js
const es = new EventSource(`/api/deploy/stream/${jobId}`);
es.addEventListener('log',   e => appendLog(JSON.parse(e.data).line));
es.addEventListener('stage', e => updateStage(JSON.parse(e.data)));
es.addEventListener('done',  e => { es.close(); onDeployDone(JSON.parse(e.data)); });
es.addEventListener('error', e => { es.close(); onDeployError(JSON.parse(e.data)); });
window.addEventListener('beforeunload', () => es.close());
```

События от бэкенда:
- `log` — `{ line: "..." }`
- `stage` — `{ name: "xray", status: "running|done|failed" }`
- `done` — `{ status: "ok", summary: {...} }`
- `error` — `{ code, message }`

---

## 12. API-хелпер

```js
async function api(path, { method = 'GET', body, form } = {}) {
  const opts = { method, headers: {} };
  if (body) { opts.headers['Content-Type'] = 'application/json'; opts.body = JSON.stringify(body); }
  if (form) { opts.body = form; }
  const r = await fetch(path, opts);
  if (!r.ok) throw await r.json();
  return r.status === 204 ? null : r.json();
}
```

Файлы — только через `FormData`.

---

## 13. UX-требования

- **Прогрессивное раскрытие** секций по галочкам.
- **Автосохранение формы** в `localStorage`.
- **Модалки** кастомные (не `confirm()`), JARVIS-стиль (blur, glow).
- **Модалки-подтверждения** только для: удаление клиента, ротация ключей, импорт секретов.
- **Тосты** — правый верхний угол, стек, авто-скрытие 4s.
- **Live-валидация** (debounce 300ms).
- **Кнопки во время запросов** — спиннер + disable.
- **Адаптив** — desktop-first, работает до 768px, мобила best effort.
- **Один источник правды** — `state`, перерисовка через `render()`.

### Клавиатура

| Клавиша | Действие |
|---|---|
| `Tab` / `Shift+Tab` | навигация |
| `Enter` | запуск `[▸ DEPLOY]` (если фокус не в текстовом поле) |
| `Esc` | закрыть overlay / модалку |
| `Space` | переключить чекбокс в фокусе |
| `←` / `→` | выбор в radio-группе в фокусе |

---

## 14. Секреты в UI

- CF Token, SSH-пароль — `type="password"` + `[👁]`.
- Пути к PEM — text-инпуты + `[ select ]`.
- **Сохраняются в `localStorage`** (приложение локальное, разрешено).
- Экспорт/импорт секретов — файлами, как в бэкенд-TZ.
- Кнопки `[⎘ copy]` / `[⎘ paste]` — для отдельных полей.

---

## 15. Язык и тон

- **English** (UI-текст).
- Готово к i18n: тексты в `i18n.en = {...}`.
- Тон — сухой технический, в духе терминала Tony Stark:
  - `Initialize deployment?` вместо длинных формулировок.
  - `Deployment complete.` / `Deploy failed: <reason>`.
  - `Copied.` для тостов.
- **Эмодзи нет**, кроме 🔨 в логотипе.

---

## 16. Мониторинг (SERVICES)

- Polling `GET /api/services/status?ip=...` каждые 5s.
- Точка `●` пульсирует при active.
- Индикатор `[◉ status]` в хедере — тоже пульсирует, если идёт деплой **или** есть failed сервис.

---

## 17. Что НЕ делаем

- Сборщики (Vite/npm/Webpack).
- React/Vue/Svelte.
- Светлая тема.
- Мобильное приложение.
- PWA / оффлайн-режим.
- xterm.js и встроенный терминал.
- QR-коды.
- WebSocket (только SSE).
- i18n (задел есть, RU не реализуем).
- CLI-команды (задел в нижней панели есть, реализация — потом).

---

## 18. Критерии готовности

1. `http://127.0.0.1:8000/` открывается, консоль чистая.
2. Секции появляются/скрываются по галочкам.
3. Форма восстанавливается из `localStorage` (включая секреты).
4. `[▸ DEPLOY]` запускает деплой, overlay выезжает, логи стримятся.
5. Overlay закрывается `[×]` / `Esc`, поля редактируются, `[◉ status]` открывает заново.
6. Прогресс-бар этапов обновляется в реальном времени.
7. После успеха появляются CLIENTS и SERVICES, flash зелёного свечения.
8. Экспорт/импорт секретов работают.
9. Адаптив до 768px.
10. Клавиатурная навигация работает.
11. Lighthouse Performance ≥ 90.
12. Все анимации — в рамках JARVIS-концепции (fade, slide, glow, scan).

---

## 19. Future work: Docker-образ

В будущей итерации весь проект (FastAPI + Ansible + web) упаковывается в **один Docker-образ** для максимального удобства запуска: `docker run -p 8000:8000 -v ./data:/app/data vpnforge`.

Требования к текущей итерации, чтобы не блокировать это:
- Никаких абсолютных путей в коде — только через `Path` от настроек.
- Все зависимости — в `pyproject.toml` + системный Ansible ставится отдельно (в Dockerfile будет отдельный слой).
- `data/` — единственная папка, которая должна быть смонтирована.
- `web/` — встроена в образ.
- Никаких обращений к `~/.ssh` напрямую — пользователь монтирует ключи сам.
