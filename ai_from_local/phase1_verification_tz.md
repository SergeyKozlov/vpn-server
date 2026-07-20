# ТЗ — Проверка (verification) Фазы 1 VPN-Project на сервере

> **Исполнитель:** Claude Code, запущенный НА сервере (Debian 12, `92.60.75.196`, 1 vCPU / 1 GB RAM).
> **Тип задачи:** только диагностика/проверка. **Ничего не чинить и не переустанавливать** без явного запроса — задача снять факты и выдать отчёт pass/fail. Единственная запись в систему — временный тестовый пользователь в smoke-тесте (раздел 7), который ОБЯЗАТЕЛЬНО удаляется в разделе 8.
> **Источники истины:** `server_CLAUDE.md` (состояние репо), `.env` (секреты/пути), `docker-compose.yml`, `Architecture_Concept_VPN_Project.md` (AC-*), `Technical Reference … Phase 1`.

---

## 0. Принципы выполнения (обязательны)

- **0.1. Ничего не хардкодить.** Имена контейнеров, `webBasePath`, id inbound'а, имя БД/пользователя Postgres, домен API, порты — **обнаруживать** из `.env`, `docker compose config`, `server_CLAUDE.md` и логов. Если значение не найдено — записать в отчёт как `UNKNOWN`, не выдумывать.
- **0.2. Не деструктивно.** Никаких `down -v`, `DROP`, `TRUNCATE`, пересборок, правок конфигов. Только чтение + один временный тест-юзер с гарантированной уборкой.
- **0.3. Идемпотентность smoke-теста.** Тестовый email должен быть уникальным для прогона (например `verify_<unixtime>@local.test`), чтобы повторный запуск не падал на UNIQUE-констрейнте.
- **0.4. Секреты не печатать.** Пароли/токены/ключи из `.env` в отчёт не выводить — только факт наличия (`present`/`missing`) и, где нужно, длину.
- **0.5. Формат результата каждого шага:** `PASS` / `FAIL` / `WARN` / `SKIP` + короткое фактическое обоснование (что реально увидели). Итог — сводная таблица (раздел 9).
- **0.6. Подстановки.** Ниже в командах плейсхолдеры вида `<PG_USER>`, `<DB_NAME>`, `<API_HOST>`, `<XUI_BASE>`, `<INBOUND_ID>`, `<repo>` — заменять на обнаруженные значения. Если compose задаёт имена сервисов — использовать `docker compose exec <svc>`, а не угаданные имена контейнеров.

---

## 1. Инвентаризация окружения (выполнить первым)

Собрать факты, от которых зависят остальные разделы. Записать в отчёт как «Обнаруженная конфигурация».

```bash
cd <repo>
cat server_CLAUDE.md 2>/dev/null | sed -n '1,40p'
docker compose config --services            # список сервисов
docker compose config | grep -E 'container_name|image|ports|POSTGRES_|XUI_|CF_|APP_ENC' -i
# .env: только КЛЮЧИ, без значений
sed -E 's/=.*/=<hidden>/' .env 2>/dev/null | sort
```

Из этого зафиксировать: имена сервисов (`api`/`postgres`/`caddy`/возможно `hysteria`), `<DB_NAME>`, `<PG_USER>`, `<API_HOST>` (домен API, ожидается `api.videcdn.net`), порт API (`8443`), `<XUI_BASE>` (base-URL 3X-UI с `webBasePath`), наличие ключей `APP_ENC_KEY`, `XUI_*`, `CF_API_TOKEN` в `.env`.

**PASS-критерий:** все обязательные сервисы присутствуют в compose; в `.env` есть ключи для Postgres, шифрования (`APP_ENC_KEY`), 3X-UI и Cloudflare.

---

## 2. Контейнеры, ресурсы, swap

```bash
docker compose ps
docker compose logs --tail=80 <api_svc> | grep -iE 'panic|fatal|restart|error' || echo 'no obvious errors'
docker inspect --format '{{.Name}}: restarts={{.RestartCount}}' $(docker compose ps -q)
free -h
swapon --show
```

**PASS:** все сервисы `Up` (при наличии healthcheck — `healthy`); `RestartCount` не растёт (нет рестарт-лупа); swap подключён (1–2 GB), `MemAvailable` > 0. **WARN:** swap отсутствует (риск OOM при нагрузке argon2id — отметить). **FAIL:** любой ключевой сервис в `Restarting`/`Exited`.

---

## 3. PostgreSQL + миграции (полная схема AC-DB)

```bash
docker compose exec -T <postgres_svc> psql -U <PG_USER> -d <DB_NAME> -c '\dt'
docker compose exec -T <postgres_svc> psql -U <PG_USER> -d <DB_NAME> \
  -c 'SELECT version_id, is_applied FROM goose_db_version ORDER BY id;'
```

Сверить наличие таблиц AC-DB-1…9: `regions, nodes, node_protocols, users, user_credentials, sessions, node_health, traffic_usage, subscriptions, payments` (+ `goose_db_version`).

Точечно проверить инварианты схемы:
```bash
# триггер BEFORE UPDATE на updated_at (AC-DB-0)
docker compose exec -T <postgres_svc> psql -U <PG_USER> -d <DB_NAME> -c '\d+ users' | grep -i trigger
# CHECK-констрейнты статусов (users.status, node.status и т.п.)
docker compose exec -T <postgres_svc> psql -U <PG_USER> -d <DB_NAME> \
  -c "SELECT conname FROM pg_constraint WHERE contype='c';"
# seed региона kz (нужен для /regions и /nodes)
docker compose exec -T <postgres_svc> psql -U <PG_USER> -d <DB_NAME> \
  -c "SELECT code, enabled FROM regions;"
```

**PASS:** все 10 доменных таблиц + `goose_db_version` присутствуют; все миграции `is_applied = t`; есть триггер `updated_at` на `users`; есть CHECK-констрейнты; регион `kz` заведён. **FAIL:** отсутствует таблица или есть непримененная миграция.

---

## 4. Caddy, TLS на 8443, целостность Reality на 443

```bash
ss -tlnp | grep -E ':443|:8443' || true      # 443/tcp → xray(Reality); 8443/tcp → caddy
ss -ulnp | grep -E ':8443|:8444' || true      # udp → hysteria (не конфликтует с tcp/8443)
docker compose logs <caddy_svc> | grep -iE 'certificate obtained|obtaining|dns|acme|error' | tail -20
# валидность сертификата API (должен быть Let's Encrypt, не self-signed)
curl -sSI https://<API_HOST>:8443/api/v1/config | head -1
curl -sv https://<API_HOST>:8443/api/v1/config 2>&1 | grep -iE 'issuer|subject|SSL certificate verify' | head -5
```

**PASS:** `8443/tcp` слушает Caddy; в логах Caddy есть успешное получение сертификата через DNS-01; `curl` по HTTPS проходит без ошибки верификации TLS; **443/tcp по-прежнему слушает Xray (Reality не перебит)**. **FAIL:** Reality на 443 пропал, или сертификат self-signed / TLS verify fail.

> Проверить, что 443/tcp принадлежит именно процессу Xray (3X-UI), а не Caddy — критично, иначе Фаза 1 сломала основной протокол.

---

## 5. API bootstrap-поток (AC-4)

```bash
echo '--- /regions (публичный) ---'
curl -s https://<API_HOST>:8443/api/v1/regions | jq .
echo '--- /config (публичный, длинный TTL) ---'
curl -s https://<API_HOST>:8443/api/v1/config | jq .
echo '--- /nodes без сессии (должен быть закрыт) ---'
curl -s -o /dev/null -w '%{http_code}\n' "https://<API_HOST>:8443/api/v1/nodes?region=kz"
```

Проверить в ответе `/config` поля из AC-5: `config_ttl_ms`, `health_check_url` (дефолт `https://www.google.com/generate_204`), `self_check.match_mode` ∈ {`asn`,`range`} (**не** `exact` — урок F1/F2), `ip_echo_urls`, `reconnect_backoff`.

**PASS:** `/regions` отдаёт `kz`; `/config` содержит перечисленные поля и `match_mode != exact`; `/nodes` без валидной сессии → `401` (или пустой список по бизнес-правилу AC-4.3, **не** 200 с чужими узлами). **FAIL:** `/nodes` отдаёт узлы без аутентификации.

---

## 6. Регистрация → сессия → argon2id / серверные сессии (AC-6.9)

Используем уникальный email прогона:
```bash
TS=$(date +%s); EMAIL="verify_${TS}@local.test"; PASS='S3cret!Verify1'
echo "test email: $EMAIL"

# регистрация
curl -s -X POST https://<API_HOST>:8443/api/v1/auth/register \
  -H 'Content-Type: application/json' \
  -d "{\"email\":\"$EMAIL\",\"password\":\"$PASS\"}" -w '\nHTTP %{http_code}\n'

# логин → cookie серверной сессии
curl -s -c /tmp/verify_cookies.txt -X POST https://<API_HOST>:8443/api/v1/auth/login \
  -H 'Content-Type: application/json' \
  -d "{\"email\":\"$EMAIL\",\"password\":\"$PASS\"}" -w '\nHTTP %{http_code}\n'

# проверка в БД: argon2id-формат и что хранится хэш токена, а не токен
docker compose exec -T <postgres_svc> psql -U <PG_USER> -d <DB_NAME> \
  -c "SELECT email, left(password_hash,22) AS hash_prefix, status FROM users WHERE email='$EMAIL';"
docker compose exec -T <postgres_svc> psql -U <PG_USER> -d <DB_NAME> \
  -c "SELECT s.expires_at, left(s.token_hash,12) AS th FROM sessions s JOIN users u ON u.id=s.user_id WHERE u.email='$EMAIL';"
```

**PASS:** register→`200/201`, login→`200` + Set-Cookie; `password_hash` начинается с `$argon2id$v=19$m=`; в `sessions` появилась строка, `token_hash` — хэш (не сырой токен из cookie); `users.status = 'trial'` с проставленным `trial_ends_at`. **FAIL:** пароль в БД в открытом виде / не argon2id, или сессия не серверная.

---

## 7. Smoke-тест ThreeXUIProvisioner (ядро Фазы 1, критично для v3.4.2)

Цель: доказать сквозную цепочку **user → шифрованные учётки в БД → клиент реально появился в inbound'е 3X-UI**. Форма `settings` и наличие API-Token «плавают» между версиями — проверяем именно на боевой v3.4.2.

```bash
# 7.1 — учётки в user_credentials должны быть зашифрованы (BYTEA, не читаемый UUID)
docker compose exec -T <postgres_svc> psql -U <PG_USER> -d <DB_NAME> \
  -c "SELECT uc.protocol, uc.status, octet_length(uc.credential) AS len,
             encode(substring(uc.credential from 1 for 8),'hex') AS head
      FROM user_credentials uc JOIN users u ON u.id=uc.user_id
      WHERE u.email='$EMAIL';"
```
Ожидание: минимум одна строка (VLESS; при провижининге обоих — и hysteria2), `len > 0`, `head` — бинарный мусор, а не ASCII UUID (значит AES-256-GCM отработал, не plaintext).

```bash
# 7.2 — клиент виден в панели 3X-UI. Base с webBasePath ОБЯЗАТЕЛЕН.
# Определить XUI_BASE и способ аутентификации из .env: Bearer (XUI_TOKEN) или cookie (XUI_USERNAME/XUI_PASSWORD).
# Вариант Bearer:
curl -s -H "Authorization: Bearer <XUI_TOKEN>" \
  "<XUI_BASE>/panel/api/inbounds/list" | jq -r '.obj[].clientStats[].email' | grep -F "$EMAIL" \
  && echo 'FOUND in panel' || echo 'NOT FOUND'
```

Внутренний идентификатор клиента в панели — это `email`-поле 3X-UI (вида `user_xxxx` или тот email, который провижинер использует как ключ). Найти запись, соответствующую только что созданному пользователю (сопоставить по тому, что кладёт провижинер — проверить в коде `ThreeXUIProvisioner`, какое `email` он шлёт в `addClient`).

**PASS:** учётки в `user_credentials` зашифрованы; клиент найден в `clientStats` inbound'а 3X-UI. **WARN:** `list` вернул HTML login/404 → неверный `webBasePath` **или** на этой сборке выключен API-Token — зафиксировать, каким методом реально ходит провижинер. **FAIL:** учётки в БД в открытом виде, либо клиент в панель не доехал.

> Зафиксировать для Фазы 2: фактический `webBasePath`, `<INBOUND_ID>`, и реально ли на v3.4.2 включён API-Token или провижинер использует cookie-login.

---

## 8. Уборка тестовых данных (ОБЯЗАТЕЛЬНО, даже если что-то упало выше)

```bash
# 8.1 — снять клиента с панели (не оставлять мусор в inbound'е)
#   найти clientId (UUID) тест-клиента, затем:
#   POST <XUI_BASE>/panel/api/inbounds/<INBOUND_ID>/delClient/<CLIENT_UUID>
curl -s -H "Authorization: Bearer <XUI_TOKEN>" -X POST \
  "<XUI_BASE>/panel/api/inbounds/<INBOUND_ID>/delClient/<CLIENT_UUID>" -w '\nHTTP %{http_code}\n'

# 8.2 — убрать тестового пользователя из БД.
#   Предпочтительно штатным путём (эндпоинт удаления аккаунта, если реализован в Фазе 1).
#   Если нет — прямой cleanup по каскаду (user_credentials/sessions → users):
docker compose exec -T <postgres_svc> psql -U <PG_USER> -d <DB_NAME> -c "
  DELETE FROM sessions WHERE user_id IN (SELECT id FROM users WHERE email='$EMAIL');
  DELETE FROM user_credentials WHERE user_id IN (SELECT id FROM users WHERE email='$EMAIL');
  DELETE FROM users WHERE email='$EMAIL';"

rm -f /tmp/verify_cookies.txt
```

**PASS:** тест-клиент удалён из панели (`success:true`); тест-юзер и его строки удалены из БД; подтвердить контрольным `SELECT`, что записей по `$EMAIL` не осталось. **WARN:** если в Фазе 1 предусмотрен soft-delete — использовать штатный механизм, а не физический `DELETE`, и отметить это.

---

## 9. Git

```bash
git -C <repo> status --short
git -C <repo> log --oneline -5
git -C <repo> remote -v
```

**PASS:** монорепо запушено в GitHub (`origin` указывает на GitHub), дерево чистое или расхождения объяснимы.

---

## 10. Итоговый отчёт (что вернуть пользователю)

Вывести **сводную таблицу** по разделам 1–9:

| # | Проверка | Итог | Факт (кратко) |
|---|---|---|---|
| 1 | Инвентаризация окружения | PASS/FAIL/… | … |
| 2 | Контейнеры / swap | | |
| 3 | Postgres + миграции (AC-DB) | | |
| 4 | Caddy TLS 8443 / Reality 443 цел | | |
| 5 | API bootstrap (/regions,/config,/nodes) | | |
| 6 | Регистрация / сессия / argon2id | | |
| 7 | ThreeXUIProvisioner end-to-end | | |
| 8 | Уборка тест-данных | | |
| 9 | Git | | |

Затем — блок **«Факты для Фазы 2»** (заполнить реальными значениями, скрыв секреты):
- Обнаруженные имена сервисов и `<DB_NAME>`/`<PG_USER>`.
- `<API_HOST>` и порт, статус сертификата (issuer).
- Фактический `webBasePath` и `<INBOUND_ID>` 3X-UI.
- Метод аутентификации к 3X-UI на v3.4.2: **Bearer API-Token** или **cookie-login**.
- Как в текущем деплое запущен Hysteria2 (в compose рядом с Go-стеком, либо systemd на хосте) — важно для выбора механизма `Hysteria2Provisioner` в Фазе 2.
- Наличие swap и запас RAM под argon2id.

И блок **«Проблемы / отклонения»**: любые FAIL/WARN с сырым выводом команды (без секретов), чтобы можно было разобрать до перехода к Фазе 2.

> **Главный smoke-критерий одной строкой:** зарегистрировал юзера → он в `users` (argon2id) → в `user_credentials` легли **шифрованные** учётки → тот же юзер виден в `clientStats` inbound'а 3X-UI → тест-данные убраны. Если цепочка проходит целиком — ядро Фазы 1 подтверждено.
