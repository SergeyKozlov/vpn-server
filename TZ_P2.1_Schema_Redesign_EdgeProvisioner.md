# ТЗ — P2.1: Редизайн схемы БД под AC-DB + абстракция EdgeProvisioner

> **Исполнитель:** Claude Code, запущенный НА сервере (Debian 12, `92.60.75.196`, 1 vCPU / 1 GB RAM), в каталоге монорепо `vpn-server`.
> **Место в декомпозиции Фазы 2:** первый шаг (P2.1) из пяти (P2.1–P2.5). Фундамент для всех последующих: serverside-сессии (P2.2), self-registration + триал (P2.3), bootstrap-поток `/regions`/`/config`/`/nodes` (P2.4), жизненный цикл клиента + revoke (P2.5).
> **Источники истины:** `Architecture_Concept_VPN_Project.md` (AC-*, далее — AC) и `Phase1_Audit_Report.md` (зафиксированные расхождения as-built vs AC — этот документ описывает ТЕКУЩЕЕ состояние, ТЗ описывает ЦЕЛЕВОЕ состояние после выполнения). `compass_artifact.md` — справочник по внешним API (3X-UI/Hysteria2), не архитектура.
> **Состояние данных:** в БД только тестовые/заглушечные записи (подтверждено владельцем проекта). Разрушающие операции над `clients`/`users` допустимы при условии архивирования (раздел 3.6), не физического удаления.

---

## 0. Принципы выполнения

- **0.1. Эта фаза — только схема + минимальный Go-каркас.** Бизнес-логика (регистрация, сессии, bootstrap-эндпоинты, revoke) реализуется в P2.2–P2.5, НЕ здесь. Цель P2.1: таблицы существуют, компилируется, существующий функционал (логин админа, создание клиента через 3X-UI+Hysteria2) продолжает работать без регрессии.
- **0.2. Не удалять данные физически.** Существующие `users` и `clients` переименовываются/архивируются (раздел 3), не дропаются.
- **0.3. Явные non-goals (не делать в этой задаче, чтобы не расползтись):**
  - Self-registration, `/register` — это P2.3.
  - Логика serverside-сессий (запись в `sessions` при логине) — это P2.2. В этой задаче таблица `sessions` только создаётся (пустая).
  - `/regions`, `/config`, `/nodes` эндпоинты — это P2.4.
  - `revoke`/`update`/`list` для клиентов — это P2.5.
  - Подсчёт трафика, наполнение `traffic_usage` — отложено (владелец проекта подтвердил: триал только по времени, без учёта байт). Таблица создаётся по AC-DB-8, но остаётся пустой/невостребованной до отдельной задачи в будущем.
  - Reconciler, многоузловой провижининг — при втором узле, не сейчас.
- **0.4. Регрессия недопустима.** После выполнения: `go test ./...` зелёный; `POST /login` (админ) работает; существующий сценарий создания клиента (3X-UI + Hysteria2 userpass) работает end-to-end так же, как до изменений.

---

## 1. Инвентаризация перед началом

```bash
cd <repo>
docker compose exec -T <postgres_svc> psql -U <PG_USER> -d <DB_NAME> -c '\dt'
docker compose exec -T <postgres_svc> psql -U <PG_USER> -d <DB_NAME> -c '\d+ users'
docker compose exec -T <postgres_svc> psql -U <PG_USER> -d <DB_NAME> -c '\d+ clients'
docker compose exec -T <postgres_svc> psql -U <PG_USER> -d <DB_NAME> -c "SELECT proname FROM pg_proc WHERE proname LIKE '%updated_at%';"
docker compose exec -T <postgres_svc> psql -U <PG_USER> -d <DB_NAME> -c "SELECT version();"  # нужно для gen_random_uuid(): встроено с PG13+
```

Зафиксировать: точное имя триггерной функции `updated_at` (по аудиту — `set_updated_at()`, но сверить), версию Postgres, текущий `goose_db_version`.

---

## 2. Новые миграции (goose, `migrations/`)

Нумерация продолжает существующую (текущая версия — `2`; начинать с `00003`). Каждая миграция — отдельный файл, отдельный логический шаг, чтобы откат был гранулярным. Использовать `gen_random_uuid()` (втроено в Postgres 13+, отдельного расширения не требует — если версия ниже 13, включить `CREATE EXTENSION IF NOT EXISTS pgcrypto;` первой строкой в `00003`).

### 2.1. `00003_rename_admin_table.sql` — развести админ-логин и AC-`users`

**Находка аудита, которую эта миграция закрывает:** фактическая таблица `users` — это панельный админ-логин (`username`/`password_hash`), а не конечный клиент по AC-DB-4. Переименовываем, сохраняя данные и работоспособность `/login`.

```sql
-- +goose Up
ALTER TABLE users RENAME TO admins;
-- индексы/констрейнты, если были привязаны к имени users_*, тоже переименовать по факту (проверить \d+ перед миграцией)

-- +goose Down
ALTER TABLE admins RENAME TO users;
```

> После этой миграции — обязательно поправить Go-код (раздел 4.1), иначе `/login` сломается.

### 2.2. `00004_create_users_ac.sql` — новая `users` по AC-DB-4 (конечный клиент)

```sql
-- +goose Up
CREATE TABLE users (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email               VARCHAR(320) UNIQUE NOT NULL,
    password_hash       TEXT NOT NULL,
    status              VARCHAR(16) NOT NULL DEFAULT 'trial'
                            CHECK (status IN ('trial','active','expired','blocked')),
    preferred_region_id UUID NULL,  -- FK добавится в 00007 после создания regions
    trial_ends_at       TIMESTAMPTZ NULL,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at          TIMESTAMPTZ NULL
);

CREATE TRIGGER users_set_updated_at
    BEFORE UPDATE ON users
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();  -- имя функции сверить с разделом 1

-- +goose Down
DROP TABLE users;
```

> Таблица создаётся пустой — наполнение (self-registration) в P2.3. Поле `status` со значением по умолчанию `trial`, но логика перехода статусов (AC-6.6) сюда не входит — только колонка с CHECK-констрейнтом.

### 2.3. `00005_create_user_credentials.sql` — AC-DB-5

```sql
-- +goose Up
CREATE TABLE user_credentials (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id      UUID NOT NULL REFERENCES users(id),
    protocol     VARCHAR(24) NOT NULL CHECK (protocol IN ('vless_reality','hysteria2')),
    credential   BYTEA NOT NULL,           -- шифровано AES-256-GCM (internal/crypto), см. раздел 4.2
    device_label VARCHAR(64) NULL,
    status       VARCHAR(16) NOT NULL DEFAULT 'active' CHECK (status IN ('active','revoked')),
    revoked_at   TIMESTAMPTZ NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TRIGGER user_credentials_set_updated_at
    BEFORE UPDATE ON user_credentials
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- +goose Down
DROP TABLE user_credentials;
```

### 2.4. `00006_create_sessions.sql` — AC-DB-6 (таблица only, логика в P2.2)

```sql
-- +goose Up
CREATE TABLE sessions (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id    UUID NOT NULL REFERENCES users(id),
    token_hash TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
-- журнальная по духу: без updated_at (см. AC-DB-6)

-- +goose Down
DROP TABLE sessions;
```

> В P2.1 в эту таблицу ничего не пишется — текущий `/login` продолжает использовать stateless-cookie (`internal/session`) без изменений. Замена механизма — P2.2.

### 2.5. `00007_create_regions_nodes_node_protocols.sql` — AC-DB-1/2/3 + seed текущего узла

```sql
-- +goose Up
CREATE TABLE regions (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    code       VARCHAR(16) UNIQUE NOT NULL,
    name       VARCHAR(64) NOT NULL,
    enabled    BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TRIGGER regions_set_updated_at BEFORE UPDATE ON regions
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TABLE nodes (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    region_id  UUID NOT NULL REFERENCES regions(id),
    ip         INET NOT NULL,
    hostname   VARCHAR(255) NULL,
    decoy_sni  VARCHAR(255) NULL,
    status     VARCHAR(16) NOT NULL DEFAULT 'active' CHECK (status IN ('active','blocked','maintenance')),
    enabled    BOOLEAN NOT NULL DEFAULT true,
    blocked_at TIMESTAMPTZ NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at TIMESTAMPTZ NULL
);
CREATE TRIGGER nodes_set_updated_at BEFORE UPDATE ON nodes
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TABLE node_protocols (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    node_id    UUID NOT NULL REFERENCES nodes(id),
    protocol   VARCHAR(24) NOT NULL CHECK (protocol IN ('vless_reality','hysteria2')),
    port       INTEGER NOT NULL,
    priority   SMALLINT NOT NULL DEFAULT 0,
    params     JSONB NOT NULL DEFAULT '{}',
    enabled    BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TRIGGER node_protocols_set_updated_at BEFORE UPDATE ON node_protocols
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- отложенный FK с 00004
ALTER TABLE users ADD CONSTRAINT users_preferred_region_fk
    FOREIGN KEY (preferred_region_id) REFERENCES regions(id);

-- seed: единственный текущий регион и узел (AC-0.5 — схема многоузловая, эксплуатация пока однoузловая)
INSERT INTO regions (code, name, enabled) VALUES ('kz', 'Казахстан', true);

INSERT INTO nodes (region_id, ip, hostname, decoy_sni, status, enabled)
SELECT id, '92.60.75.196', NULL, 'dl.google.com', 'active', true
FROM regions WHERE code = 'kz';

INSERT INTO node_protocols (node_id, protocol, port, priority, params)
SELECT id, 'vless_reality', 443, 10, '{}'::jsonb FROM nodes WHERE ip = '92.60.75.196';
INSERT INTO node_protocols (node_id, protocol, port, priority, params)
SELECT id, 'hysteria2', 8443, 0, '{}'::jsonb FROM nodes WHERE ip = '92.60.75.196';
-- уточнить фактический decoy_sni и порт Hysteria2 (UDP) перед применением — свериться с текущим config.yaml и inbound в 3X-UI

-- +goose Down
ALTER TABLE users DROP CONSTRAINT users_preferred_region_fk;
DROP TABLE node_protocols;
DROP TABLE nodes;
DROP TABLE regions;
```

> **Важно:** значения `decoy_sni`/порты в seed — ориентир из раннбука, ПЕРЕД применением сверить с фактическим `Caddyfile`/`config.yaml`/inbound на сервере и поправить, если разошлось.

### 2.6. `00008_create_node_health_traffic_usage.sql` — AC-DB-7/8 (создаются, не наполняются)

```sql
-- +goose Up
CREATE TABLE node_health (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    node_id    UUID NOT NULL REFERENCES nodes(id),
    checked_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    status     VARCHAR(16) NOT NULL CHECK (status IN ('ok','blocked','degraded')),
    source     VARCHAR(16) NOT NULL CHECK (source IN ('client_report','self_check')),
    detail     JSONB NULL
);

CREATE TABLE traffic_usage (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id      UUID NOT NULL REFERENCES users(id),
    node_id      UUID NULL REFERENCES nodes(id),
    period_start TIMESTAMPTZ NOT NULL,
    period_end   TIMESTAMPTZ NOT NULL,
    bytes_up     BIGINT NOT NULL DEFAULT 0,
    bytes_down   BIGINT NOT NULL DEFAULT 0,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- +goose Down
DROP TABLE traffic_usage;
DROP TABLE node_health;
```

### 2.7. `00009_create_billing_stubs.sql` — AC-DB-9 (заглушки)

```sql
-- +goose Up
CREATE TABLE subscriptions (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id    UUID REFERENCES users(id),
    plan       VARCHAR NOT NULL,
    status     VARCHAR NOT NULL,
    started_at TIMESTAMPTZ,
    ends_at    TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TRIGGER subscriptions_set_updated_at BEFORE UPDATE ON subscriptions
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TABLE payments (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id     UUID REFERENCES users(id),
    amount      NUMERIC,
    currency    VARCHAR,
    provider    VARCHAR,
    external_id VARCHAR,
    status      VARCHAR,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TRIGGER payments_set_updated_at BEFORE UPDATE ON payments
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- +goose Down
DROP TABLE payments;
DROP TABLE subscriptions;
```

### 2.8. `00010_archive_legacy_clients.sql` — не мигрировать, а сохранить как референс

**Находка аудита:** `clients` совмещает роль AC-`users` + `user_credentials` в одной строке, без модели per-device. Реальных пользователей в этой таблице нет (только тестовые записи) — построчная миграция не нужна и не имеет смысла (нет email/аутентификации, чтобы связать со новой `users`). Переименовываем для истории, не удаляем.

```sql
-- +goose Up
ALTER TABLE clients RENAME TO legacy_clients_phase1;

-- +goose Down
ALTER TABLE legacy_clients_phase1 RENAME TO clients;
```

---

## 3. Проверка seed-данных перед применением 00007

Перед запуском `00007` свериться вручную (не автоматизировать, значения критичны):
```bash
# фактический decoy SNI и порт VLESS Reality
docker compose exec -T <postgres_svc> psql ... # либо через 3X-UI API smoke, см. Phase1_Audit_Report раздел 6
cat <path-to-hysteria-config>/config.yaml | grep -A3 listen  # фактический UDP-порт Hysteria2
```
Если значения в миграции разошлись с фактом — поправить SQL перед применением, не после.

---

## 4. Go-каркас (минимальный, без бизнес-логики)

### 4.1. Обязательная правка после переименования `users`→`admins`

Найти все ссылки на таблицу `users` в контексте админ-логина и поправить на `admins`:
```bash
grep -rniE 'FROM users|INTO users|UPDATE users' --include='*.go' internal/auth internal/session cmd/createadmin
```
Обновить SQL-запросы и, если есть, имя Go-структуры (`User` → `Admin`, если она сейчас используется для панельного логина — проверить `internal/auth` на этот счёт). Цель: `POST /login` и `cmd/createadmin` работают ПОСЛЕ миграции точно так же, как ДО неё.

### 4.2. Новые доменные структуры (только структуры + там, где нужно для seed-проверки — Get/List, БЕЗ полноценного CRUD)

Добавить в `internal/domain` (или существующее подходящее место — определить по структуре репо):
```go
type User struct {
    ID                 uuid.UUID
    Email              string
    PasswordHash       string
    Status             string // trial|active|expired|blocked
    PreferredRegionID  *uuid.UUID
    TrialEndsAt        *time.Time
    CreatedAt, UpdatedAt time.Time
    DeletedAt          *time.Time
}

type UserCredential struct {
    ID           uuid.UUID
    UserID       uuid.UUID
    Protocol     string // vless_reality|hysteria2
    Credential   []byte // encrypted, see internal/crypto
    DeviceLabel  *string
    Status       string // active|revoked
    RevokedAt    *time.Time
    CreatedAt, UpdatedAt time.Time
}

type Region struct {
    ID      uuid.UUID
    Code    string
    Name    string
    Enabled bool
}

type Node struct {
    ID        uuid.UUID
    RegionID  uuid.UUID
    IP        string
    Hostname  *string
    DecoySNI  *string
    Status    string
    Enabled   bool
}

type NodeProtocol struct {
    ID       uuid.UUID
    NodeID   uuid.UUID
    Protocol string
    Port     int
    Priority int16
    Params   json.RawMessage
    Enabled  bool
}
```
`Session`, `NodeHealth`, `TrafficUsage`, `Subscription`, `Payment` — структуры не обязательны в этой задаче (нет логики, которая бы их использовала до P2.2/P2.4/будущей телеметрии); добавить только если естественно ложится в существующий стиль репозитория, иначе отложить до задачи, где они реально понадобятся.

Минимальный repository-слой (только то, что нужно проверить в acceptance, раздел 6): `RegionRepo.List()`, `NodeRepo.ListByRegion(regionID)` — используются в acceptance-проверке ниже и пригодятся P2.4 без переделки.

### 4.3. `EdgeProvisioner` — абстракция над 3X-UI и Hysteria2

**Находка аудита (AC-6.8):** сейчас `internal/clients/service.go` напрямую держит `*xui.Panel` и вызывает `internal/hysteria.SyncUsers` — нет общего интерфейса. Это чистый рефактор без изменения поведения — вводим сейчас, чтобы P2.5 (revoke) и будущий второй узел не переделывали это заново.

Создать `internal/provisioner`:
```go
package provisioner

type EdgeProvisioner interface {
    AddUser(ctx context.Context, cred UserCredentialInput) error
    RemoveUser(ctx context.Context, protocol, identifier string) error
    RotateCredential(ctx context.Context, old, new UserCredentialInput) error
    GetTraffic(ctx context.Context, identifier string) (TrafficStats, error)
}
```
Реализации:
- `ThreeXUIProvisioner` — оборачивает существующий `internal/xui.Panel` (методы `AddClient`/`UpdateClient`/`DeleteClient`/`GetClientTraffics` уже есть, по аудиту раздел 9 — рабочие; здесь их просто прячем за интерфейс, не переписываем).
- `Hysteria2Provisioner` — оборачивает существующий `internal/hysteria.SyncUsers`/`SetUsers`.

**Обязательно вместе с рефактором — закрыть подтверждённый в аудите баг:** `internal/hysteria/config.go` (`SetUsers`/`Save`) — при пустой карте `userpass` полностью пропадает из YAML, сервер падает с `FATAL: auth.userpass: empty auth userpass` (воспроизведено в логах, раздел 7 аудита). В `Hysteria2Provisioner.RemoveUser` (и в лежащем под ним `SetUsers`) добавить защиту: если после удаления карта пуста — не писать `auth.type: userpass` с пустым `userpass` в конфиг; либо оставить последнего технического placeholder-пользователя, либо явно остановить/не перезапускать сервис с валидным сообщением в лог вместо `FATAL`-краша. Выбрать более простой вариант по месту, задокументировать решение в комментарии к коду.

**Правка `internal/clients/service.go`:** заменить прямые вызовы `*xui.Panel` и `hysteria.SyncUsers` на вызовы через `EdgeProvisioner` (внедрение зависимости в конструктор `Service`). Поведение (включая существующий компенсирующий rollback при частичном сбое) должно остаться идентичным — это рефактор, не переписывание логики.

---

## 5. Acceptance-проверка (выполнить после применения, зафиксировать в отчёте)

| # | Проверка | Команда/способ | Ожидаемо |
|---|---|---|---|
| 1 | Полная схема AC-DB | `\dt` | `admins, users, user_credentials, sessions, regions, nodes, node_protocols, node_health, traffic_usage, subscriptions, payments, legacy_clients_phase1, goose_db_version` — все присутствуют |
| 2 | `admins` содержит старые данные | `SELECT count(*) FROM admins;` | ≥1 (старый админ не потерян) |
| 3 | `legacy_clients_phase1` содержит старые данные | `SELECT count(*) FROM legacy_clients_phase1;` | = кол-ву строк в бывшей `clients` до миграции |
| 4 | Seed региона/узла | `SELECT code FROM regions;` / `SELECT ip FROM nodes;` | `kz` / `92.60.75.196` |
| 5 | `node_protocols` для узла | `SELECT protocol, port FROM node_protocols;` | `vless_reality/443`, `hysteria2/<факт.порт>` |
| 6 | UUID PK везде в новых таблицах | `\d+ users`, `\d+ nodes` и т.д. | тип `id` = `uuid` |
| 7 | Триггер `updated_at` на новых таблицах с этим полем | `\d+ users` → раздел Triggers | присутствует |
| 8 | Регрессия: логин админа | `POST /login` с существующими кредами | `200`, как раньше |
| 9 | Регрессия: создание клиента end-to-end | Повторить smoke-тест из `TZ_Phase1_Verification.md` раздел 7 (через новый `EdgeProvisioner`) | клиент доезжает до 3X-UI inbound, как раньше |
| 10 | `go test ./...` | | всё зелёное |
| 11 | Баг пустого `userpass` закрыт | Смоделировать удаление последнего пользователя у `Hysteria2Provisioner.RemoveUser` (на тестовых данных) | сервис не падает с `FATAL` |

---

## 6. Отчёт

Сформировать отчёт по разделу 5 (таблица факт/ожидание для каждого пункта) и по каждой выполненной миграции — статус применения (`goose status`).

**Отчёт обязательно сохранить в файл `P2.1_Schema_Redesign_Report.md` в корне репозитория и закоммитить.** Вывод в терминал/чат можно оставить как есть, но именно сохранение в md-файл в репозитории — обязательный результат задачи, не опционально: этот отчёт станет источником фактов для следующей задачи (P2.2).
