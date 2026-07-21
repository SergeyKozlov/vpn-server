# Аудит Фазы 1: сверка кода с Architecture_Concept_VPN_Project.md

## 0. Проверка источников (обязательный первый пункт)

- `Architecture_Concept_VPN_Project.md` — **присутствует**, `/root/vpn/Architecture_Concept_VPN_Project.md` (33583 байт, дата в шапке 19.07.2026). Аудит продолжается.
- `compass_artifact.md` — присутствует, `/root/vpn/compass_artifact.md`.
- `project_phase1_scope.md` — **в репозитории отсутствует** (`find` не нашёл ни одного совпадения). Файл существует только как запись авто-памяти Claude Code (`project_phase1_scope.md` вне репо), в дереве проекта нет ни его, ни каталога `openspec/`. Контекст «почему так вышло» беру из архитектурного анализа кода, а не из этого файла.

---

## 2. Инвентаризация

```
git log --oneline -20  → 16 коммитов, HEAD de4f5b5 "feat: add Caddy and Hysteria2 services to docker-compose"
git remote -v          → origin git@github.com:SergeyKozlov/vpn-server.git
openspec/               → отсутствует
```

Go-модуль `vpn-api` в `api/`:
- `cmd/api`, `cmd/createadmin`
- `internal/`: `api`, `auth`, `session`, `clients`, `xui`, `hysteria`, `crypto`, `password`, `config`, `database`

`docker-compose.yml` сервисы: `3x-ui` (network_mode host), `postgres` (`vpn-postgres`, DB `vpn`, user `vpn`), `hysteria2` (network_mode host), `caddy` (network_mode host, cloudflare-DNS образ).

---

## 3. Схема БД (AC-DB)

`\dt` в `postgres`/`vpn`: только **`users`**, **`clients`**, **`goose_db_version`** (версии 0,1,2, все `is_applied=t`).

| AC-ID | Сущность по AC | Есть в БД? | Расхождение с AC |
|---|---|---|---|
| AC-DB-1 | `regions` | Нет | ОТСУТСТВУЕТ — нет региональности вообще, 1 хардкод-узел |
| AC-DB-2 | `nodes` (`decoy_sni`, soft-delete) | Нет | ОТСУТСТВУЕТ |
| AC-DB-3 | `node_protocols` | Нет | ОТСУТСТВУЕТ |
| AC-DB-4 | `users` (status, `trial_ends_at`, soft-delete) | Есть, но другая схема | РАСХОЖДЕНИЕ — факт: `users(id BIGSERIAL, username TEXT UNIQUE, password_hash, created_at, updated_at)`. Нет `email`, `status`, `preferred_region_id`, `trial_ends_at`, `deleted_at`. `id` — `bigint`, не `UUID` |
| AC-DB-5 | `user_credentials` (шифр. `credential`, per-device) | Нет отдельно | РАСХОЖДЕНИЕ — эквивалент слит в `clients` (см. ниже) |
| AC-DB-6 | `sessions` (serverside, `token_hash`) | Нет | ОТСУТСТВУЕТ — см. раздел 5 |
| AC-DB-7 | `node_health` | Нет | ОТСУТСТВУЕТ |
| AC-DB-8 | `traffic_usage` | Нет | ОТСУТСТВУЕТ |
| AC-DB-9 | `subscriptions`/`payments` (заглушки) | Нет | ОТСУТСТВУЕТ (по AC это и так заглушка/бэклог, но заглушек-таблиц тоже нет) |

**AC-DB-0 (общие соглашения) — построчно:**
- PK = UUID: **не соблюдено** — оба существующих PK (`users.id`, `clients.id`) это `BIGSERIAL`/`bigint`, не `UUID`.
- `TIMESTAMPTZ` + UTC: **соблюдено** (`created_at`/`updated_at TIMESTAMPTZ NOT NULL DEFAULT now()` в обеих таблицах).
- Триггер `updated_at BEFORE UPDATE`: **соблюдено** — `set_updated_at()` + `users_set_updated_at`/`clients_set_updated_at` (миграции `00001`, `00002`).
- Soft-delete (`deleted_at`): **не соблюдено** — ни в `users`, ни в `clients` колонки `deleted_at` нет; `clients` использует `enabled BOOLEAN` вместо soft-delete, `users` не имеет вообще никакого механизма деактивации.
- Шифрование секретных колонок: **соблюдено для тоннельных секретов** — `clients.vless_uuid_enc`, `clients.hysteria2_password_enc` типа `BYTEA`, шифруются через `internal/crypto.AESGCM` (AES-256-GCM). `users.password_hash` — хэш (argon2id), не шифрование, что верно по AC-DB-0.

**Слияние `users`+`user_credentials` в `clients` (AC-6.2):** факт — as-built `clients` совмещает то, что AC разносит на две сущности: `clients` одновременно хранит бизнес-атрибуты клиента (`email`, `traffic_limit_bytes`, `limit_ip`, `expires_at`, `enabled` — аналог `users` по AC) **и** сами тоннельные учётки (`vless_uuid_enc`, `hysteria2_username`, `hysteria2_password_enc` — аналог `user_credentials` по AC) в одной строке-таблице. При этом факт-таблица `users` — это отдельная и никак не связанная сущность: она хранит **панельного администратора** (`username`/`password_hash` для `/login`), а не конечного VPN-пользователя. То есть в коде существуют два разных "users": AC-`users` (клиент сервиса, конечный потребитель VPN) фактически не реализован как отдельная сущность — его роль частично играет `clients` (без аутентификации, без пароля, без статуса), а таблица с именем `users` в БД — это админ-аккаунт для входа в API, не имеющий отношения к AC-DB-4. Модель «credential на устройство» (несколько строк на одного пользователя) также отсутствует: `clients` — одна строка на одного «клиента» (1 VLESS-UUID + 1 Hysteria2-пароль в одной записи), множественности устройств нет.

---

## 4. Модель доступа: регистрация и статусы (AC-6.6, AC-6.9)

- **AC-6.9 (регистрация):** статус **РАСХОЖДЕНИЕ**. AC требует self-registration (email+пароль, `password_hash` argon2id). Факт: self-registration отсутствует. Единственный способ создать VPN-клиента — авторизованный `POST /clients` (`api/internal/api/router.go:29`, за `RequireAuth`); единственный способ создать пользователя, способного логиниться — CLI `cmd/createadmin` (`api/cmd/createadmin/main.go:1-3`: «Run once, manually, on the server — there is no public registration endpoint»). Пароль хэшируется argon2id (`internal/password/password.go`) — этот механизм совпадает с AC, но применяется к панельному админу, а не к self-registered пользователю сервиса.
- **AC-6.6 (статусы/триал):** статус **ОТСУТСТВУЕТ**. Поиск `trial|status.*(active|expired|blocked)|trial_ends_at` по всем `*.go` — 0 совпадений. Ни поля `status`, ни понятия триала в коде и схеме нет вообще (не только переходы состояний, которые по AC отложены в биллинг-чат, — само поле отсутствует).

---

## 5. Сессии (AC-6.9 — критическое расхождение)

Статус: **РАСХОЖДЕНИЕ**, подтверждено точно.

- AC-6.9 требует: сессии serverside, токен хранится в БД (`sessions.token_hash`), не JWT/stateless — ради мгновенного отзыва.
- Факт: `api/internal/session/session.go:1-3` — дословно: *«Package session implements stateless, HMAC-signed session tokens carried in a cookie: no session table, no server-side revocation before expiry»*. Механизм — HMAC-SHA256 подписанный токен (`Signer.Sign`/`Verify`, `session.go`), кодирует `userID` + `expiresAt`, TTL = 24 часа (константа `TTL`), передаётся в cookie `vpn_session` (`middleware.go:11`). В БД ничего не пишется при логине — `\dt` подтверждает отсутствие таблицы `sessions`. Отзыв до истечения TTL невозможен (нет server-side состояния, которое можно инвалидировать).

---

## 6. Bootstrap-поток API (AC-4, AC-5)

Фактические роуты (`api/internal/api/router.go:23-29`): `GET /healthz`, `POST /login`, `POST /logout`, `POST /clients` (за `RequireAuth`).

| AC-ID | Требуемый эндпоинт | Статус | Факт |
|---|---|---|---|
| AC-4.1 | `GET /api/v1/regions` | ОТСУТСТВУЕТ | нет ни `/regions`, ни версионирования `/api/v1/*` в роутере вообще |
| AC-4.2 | `GET /api/v1/config` (поля AC-5) | ОТСУТСТВУЕТ | нет `/config`; соответственно ни `config_ttl_ms`, ни `health_check_url`, ни `self_check.match_mode`, ни `ip_echo_urls`, ни `reconnect_backoff` нигде в коде не найдены |
| AC-4.3 | `GET /api/v1/nodes?region=` | ОТСУТСТВУЕТ | нет `/nodes`; клиент вообще не получает свои учётки через API-запрос под сессией — учётки видны только в ответе `POST /clients` в момент создания (админом) |

Весь namespace `/api/v1/*` из AC не реализован; текущий API — CRUD одного ресурса (`clients`) под админской сессией, а не bootstrap-поток конечного клиента.

---

## 7. Провижининг и EdgeProvisioner (AC-6.2…6.8, AC-3)

- **AC-6.8 (абстракция EdgeProvisioner):** статус **ОТСУТСТВУЕТ**. Grep по `EdgeProvisioner|ThreeXUIProvisioner|Hysteria2Provisioner` — 0 совпадений. Провижининг прибит гвоздями: `internal/clients/service.go` напрямую держит `*xui.Panel` и вызывает `internal/hysteria.SyncUsers` — нет общего интерфейса с методами `AddUser/RemoveUser/RotateCredential/GetTraffic`, которые можно было бы подменить адаптером.
- **AC-6.2/6.3 (разделение user_id / учёток, credential на устройство):** РАСХОЖДЕНИЕ, см. раздел 3 — `clients` совмещает обе роли в одной строке, без модели «на устройство».
- **AC-6.4 (провижининг + отзыв):** ЧАСТИЧНО. Есть: создание (`Service.Create`, `service.go:55`) с компенсирующим откатом при частичном сбое (`s.panel.DeleteClient` + `s.deleteClientRow` при неудаче синхронизации Hysteria2, `service.go:112-120` — это откат создания, а не пользовательский revoke). Нет: публичного API для отзыва (`RemoveUser`/`DELETE /clients/{id}`), нет `Update`/`List` — только `Create` вызывается извне; `xui.Panel.DeleteClient`/`UpdateClient` существуют (`internal/xui/client.go:131,145`) но используются исключительно как внутренний rollback-механизм, не как эксплуатационный revoke-путь.
- **AC-3.1 (оба протокола на узле):** РЕАЛИЗОВАНО по составу — `docker-compose.yml` поднимает и `3x-ui` (VLESS), и `hysteria2` контейнер. Факт эксплуатации на момент проверки: `docker compose ps -a` показывает `hysteria2` — `Exited (0) 2 hours ago`, то есть в момент аудита контейнер не запущен (последний штатный `shutdown`/`stop`, не крэш).
- **Известный баг ресинка Hysteria2 на пустом `userpass`:** статус **НЕ ОБРАБОТАНО, воспроизведено в логах**. `internal/hysteria/config.go:26` — `UserPass map[string]string \`yaml:"userpass,omitempty"\`` — при пустой карте поле полностью пропадёт из YAML при `Save`, оставив `auth.type: userpass` без `userpass`. Никакой проверки на пустую карту нет ни в `SetUsers` (`config.go:44-47`), ни в `syncHysteriaUsers` (`service.go:145-173`). Живое подтверждение из `docker compose logs hysteria2`:
  ```
  FATAL failed to load server config {"error": "invalid config: auth.userpass: empty auth userpass"}
  ```
  (повторяется 6 раз подряд ~14:34:15-30, затем контейнер стартует успешно, когда карта стала непустой). Поскольку публичного revoke/delete-пути сейчас нет (см. AC-6.4 выше), в штатной эксплуатации через API это не триггерится — баг проявляется только при ручном/внешнем удалении всех строк `clients` или прямой правке `config.yaml`.

---

## 8. Телеметрия трафика (AC-6.5)

Статус: **ОТСУТСТВУЕТ**, подтверждено.

`xui.Panel` имеет методы `GetClientTraffics`/`GetClientTrafficsByID` (`internal/xui/client.go:152,168`), но они не вызываются нигде вне тестов (`grep` не находит вызовов из `clients`, `cmd/api` или какого-либо периодического job'а). Проверка на `ticker|cron|periodic|go func` вне тестов даёт единственное совпадение — `main.go:82` (не относится к телеметрии, это точка входа HTTP-сервера). Нет ни таблицы `traffic_usage`, ни какого-либо расчёта лимита/квоты в бизнес-логике — поля `traffic_limit_bytes` в `clients` только сохраняется и прокидывается в 3X-UI (`TotalGB`), сам 3X-UI обеспечивает контроль лимита на своей стороне (что противоречит AC-6.5, который требует расчёт лимита именно на стороне бизнес-логики, не делегируя 3X-UI).

---

## 9. Крипто/безопасность (AC-DB-0, compass §5)

Статус: **РЕАЛИЗОВАНО**, совпадает с AC и compass.

- AES-256-GCM: `internal/crypto/crypto.go` — `AESGCM` над `crypto/aes`+`crypto/cipher`, 32-байтный ключ (`KeySize = 32`), случайный nonce на сообщение, применяется к `vless_uuid_enc`/`hysteria2_password_enc`.
- argon2id: `internal/password/password.go` — параметры явно занижены под 1 GB RAM хост (`Memory: 32*1024`, `Iterations: 3`, `Parallelism: 1`), с комментарием со ссылкой на диапазон из `compass_artifact.md`.

---

## 10. Итоговый отчёт

### 10.1. Сводная таблица AC-статусов

| AC-ID | Что требует AC | Статус | Факт |
|---|---|---|---|
| AC-DB-1 `regions` | таблица регионов | ОТСУТСТВУЕТ | нет в `\dt` |
| AC-DB-2 `nodes` | таблица узлов, decoy_sni, soft-delete | ОТСУТСТВУЕТ | нет в `\dt` |
| AC-DB-3 `node_protocols` | протоколы на узел | ОТСУТСТВУЕТ | нет в `\dt` |
| AC-DB-4 `users` | email/status/trial/soft-delete, UUID PK | РАСХОЖДЕНИЕ | факт-`users` — админ-логин (`username`, `bigint` PK), нет email/status/trial/deleted_at |
| AC-DB-5 `user_credentials` | шифр. credential, per-device | РАСХОЖДЕНИЕ | слито в `clients`, без модели per-device |
| AC-DB-6 `sessions` | serverside токены | ОТСУТСТВУЕТ | подписанные stateless cookie, см. §5 |
| AC-DB-7 `node_health` | append-only телеметрия узлов | ОТСУТСТВУЕТ | нет в `\dt` |
| AC-DB-8 `traffic_usage` | временной ряд трафика | ОТСУТСТВУЕТ | нет в `\dt`, нет job'а сбора |
| AC-DB-9 billing-заглушки | subscriptions/payments | ОТСУТСТВУЕТ | нет в `\dt` |
| AC-DB-0 общие соглашения | UUID PK/TIMESTAMPTZ/триггер/soft-delete/шифрование | ЧАСТИЧНО | TIMESTAMPTZ ✓, триггер ✓, шифрование секретов ✓; UUID PK ✗ (bigint), soft-delete ✗ |
| AC-4.1/4.2/4.3 | bootstrap-эндпоинты | ОТСУТСТВУЕТ | роутер содержит только `/healthz,/login,/logout,/clients` |
| AC-5 | поля `/config` | ОТСУТСТВУЕТ | эндпоинта `/config` нет вообще |
| AC-6.2 | разделение user_id / учёток | РАСХОЖДЕНИЕ | одна таблица `clients` вместо двух сущностей |
| AC-6.4 | провижининг + revoke | ЧАСТИЧНО | Create + rollback есть; публичный revoke/update/list — нет |
| AC-6.5 | телеметрия трафика | ОТСУТСТВУЕТ | методы есть в `xui.Panel`, не вызываются нигде вне тестов |
| AC-6.6 | статусы + триал | ОТСУТСТВУЕТ | поле `status`/`trial` нигде не встречается |
| AC-6.8 | EdgeProvisioner абстракция | ОТСУТСТВУЕТ | `clients.Service` напрямую держит `*xui.Panel` и `hysteria.SyncUsers` |
| AC-6.9 | регистрация email+пароль | РАСХОЖДЕНИЕ | self-registration нет; доступ выдаёт админ (`createadmin` + `POST /clients`) |
| AC-6.9 | serverside-сессии в БД | РАСХОЖДЕНИЕ | HMAC-подписанные stateless cookie, TTL 24ч, нет таблицы `sessions` |
| AC-3.1 | оба протокола на узле | ЧАСТИЧНО | оба сервиса в compose; на момент проверки `hysteria2` контейнер `Exited (0)` |
| AC-DB-0 | (см. выше, дублирует строку) | — | — |

### 10.2. Ключевые A/B-расхождения

1. **Сессии.** AC: serverside-токен в таблице `sessions` (`token_hash`), мгновенный отзыв. Факт: `internal/session/session.go` — stateless HMAC-SHA256-подписанный токен в cookie `vpn_session`, TTL 24 часа фиксированный, никакой записи в БД при логине, отзыв до истечения TTL невозможен в принципе (нет состояния для инвалидации).
2. **Регистрация.** AC: self-registration email+пароль с назначением триала. Факт: публичной регистрации нет; единственный вход в систему — ручной `cmd/createadmin` для панельного пользователя плюс `POST /clients` (под сессией того же панельного пользователя) для создания VPN-клиента. Модель полностью admin-provisioned, не self-service.
3. **Схема БД.** AC: 9 сущностей (`regions`, `nodes`, `node_protocols`, `users`, `user_credentials`, `sessions`, `node_health`, `traffic_usage`, `subscriptions`/`payments`), UUID PK везде, soft-delete на `users`/`nodes`. Факт: 2 прикладные таблицы — `users` (админ-логин, не AC-`users`) и `clients` (совмещает роль AC-`users`+`user_credentials` в одной записи, без per-device множественности). PK — `BIGSERIAL`, не `UUID`. Soft-delete нигде не реализован (`clients.enabled` — булев флаг, не `deleted_at`).

### 10.3. Совпадает с AC (сохраняем в Фазе 2)

- Крипто: AES-256-GCM для секретных колонок (`internal/crypto`) — параметры и подход соответствуют AC-DB-0 и compass §5.
- Argon2id-хэширование паролей (`internal/password`), параметры уже занижены под 1GB RAM хост.
- xui-клиент (`internal/xui`): `AddClient/UpdateClient/DeleteClient/GetClientTraffics` — рабочая обёртка над 3X-UI Bearer-token API, готовый строительный блок для будущего `EdgeProvisioner`.
- Hysteria2-конфиг (`internal/hysteria`): чтение/запись `config.yaml` с сохранением сторонних ключей через `Extra` (безопасно для ручных правок), reload через внешнюю команду.
- Postgres + goose: миграции встроены и применяются (`goose_db_version` актуален), триггер `updated_at BEFORE UPDATE` работает.
- Caddy + TLS: контейнер `caddy` (cloudflare-DNS образ) поднят и работает.
- Провижининг-ядро с компенсирующим rollback при частичном сбое создания клиента (`clients.Service.Create`) — паттерн общий, годится под расширение к полноценному EdgeProvisioner.

### 10.4. Не покрыто аудитом / UNKNOWN

- **`project_phase1_scope.md`** — отсутствует в репозитории физически; описание «as-built модели» в этом отчёте построено напрямую по коду, а не по этому файлу. Причина: файл существует только в памяти Claude Code вне репо.
- Состояние 3X-UI панели изнутри (реальные inbound'ы, реальные клиенты в панели, соответствие БД `clients` фактическому состоянию Xray) — не проверялось: аудит по ТЗ ограничен кодом/схемой/git, не живым состоянием панели через её API.
- Причина остановки контейнера `hysteria2` (`Exited (0)`) на момент проверки — по логам это штатный `shutdown` (не крэш-луп прямо сейчас), но точная причина последней остановки (ручная команда/деплой/health-check) не установлена — вне области read-only-аудита кода.
- Конфигурация `Caddyfile` (маршруты, домены, upstream) не сверялась построчно с AC-1 (DNS/домены) — не запрашивалось в ТЗ явно, требует отдельного прохода.
- Тестовое покрытие (`*_test.go`) не оценивалось на предмет полноты — ТЗ требовало сверку структуры кода/схемы с AC, а не аудит качества тестов.
