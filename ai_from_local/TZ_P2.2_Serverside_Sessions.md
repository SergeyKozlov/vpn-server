# ТЗ — P2.2: Serverside-сессии (замена stateless-cookie на token_hash в БД)

> **Исполнитель:** Claude Code, запущенный НА сервере.
> **Место в декомпозиции Фазы 2:** второй шаг (P2.2) из пяти (P2.1–P2.5). Фундамент для следующих фаз: сессии используются в bootstrap-потоке (P2.4) и везде, где нужна аутентификация.
> **Источники истины:** `Architecture_Concept_VPN_Project.md` (AC-6.9: serverside-сессии, token в БД, НЕ JWT), `ai_from_local/Phase1_Audit_Report.md` (текущее состояние: stateless-cookie).
> **Состояние БД:** таблица `sessions` создана в P2.1 (пустая); админы отделены в `admins`, конечные клиенты в `users`; миграции полные.

---

## 0. Принципы выполнения

- **0.1. Это кодовый рефакторинг, не схема БД.** Таблица `sessions` уже существует, не трогаем миграции. Меняем только `internal/session`, `internal/auth`, `internal/api/login.go` и зависимые тесты.
- **0.2. Не менять логику остального кода.** `middleware.RequireAuth`, провижининг, клиентский lifecycle, EdgeProvisioner остаются как есть. Меняется только то, как проверяется наличие и валидность сессии.
- **0.3. Регрессия недопустима.** `POST /login` работает как раньше (возвращает 204, пользователь залогинен), `POST /logout` работает (удаляет сессию). Существующие клиенты, залогиненные под старым механизмом, автоматически НЕ мигрируются (это разные cookie-форматы, поэтому при развертывании это одноразовый re-login).
- **0.4. Non-goals (не делать):** периодическая чистка expired сессий (можно отложить на отдельный job/задачу), 2FA, rate-limit на login (уже есть из P2.1, не трогаем), logout all других сессий пользователя (реализуем один logout, не batch).

---

## 1. Инвентаризация перед началом

```bash
cd <repo>
# текущая реализация сессий
sed -n '1,50p' internal/session/*.go
# текущая реализация логина
sed -n '1,80p' internal/auth/*.go
sed -n '1,80p' internal/api/login.go
# что лежит в таблице sessions сейчас
docker compose exec -T <postgres_svc> psql -U <PG_USER> -d <DB_NAME> \
  -c "SELECT count(*) FROM sessions; \d+ sessions"
# текущая middleware для проверки auth
grep -rn "middleware.RequireAuth\|IsLogin\|session" --include='*.go' internal/api/ | head -20
```

Зафиксировать: текущий пакет/функции в session (вероятно `secureookie` или `sessions` из Gin), текущий механизм проверки cookie (подпись?), наличие/отсутствие token_hash в коде.

---

## 2. Новая реализация `internal/session`

**Цель:** заменить stateless подписанную cookie на serverside token-based auth.

### 2.1. Структуры

```go
package session

import (
    "context"
    "database/sql"
    "time"
    "github.com/google/uuid"
)

// SessionManager управляет serverside-сессиями в БД
type SessionManager struct {
    db *sql.DB
    secretKey []byte  // для хэширования token перед записью в БД
}

// Session — модель из таблицы (не отправляется клиенту)
type Session struct {
    ID        uuid.UUID
    UserID    uuid.UUID
    TokenHash string    // хэш токена (он хранится в БД, не сам токен)
    ExpiresAt time.Time
    CreatedAt time.Time
}

// Token — что отправляем на клиента (в cookie или заголовке)
type Token struct {
    Value  string    // человекочитаемый токен для отправки
    Expiry time.Duration  // TTL (AC-6.9 не задаёт, дефолт 24 часа)
}
```

### 2.2. Главные методы

```go
// CreateSession генерирует новый token, хэширует его, сохраняет в БД, возвращает оригинальный token
func (sm *SessionManager) CreateSession(ctx context.Context, userID uuid.UUID, ttl time.Duration) (*Token, error) {
    // 1. Генерировать random token (достаточно 32 байта, закодировать base64 или hex)
    // 2. Хэшировать token (например sha256) → token_hash
    // 3. Вставить в sessions(id, user_id, token_hash, expires_at, created_at)
    // 4. Вернуть Token с Value = оригинальный token (НЕ хэш)
}

// ValidateToken получает token от клиента, проверяет его наличие и валидность в БД
func (sm *SessionManager) ValidateToken(ctx context.Context, token string) (*Session, error) {
    // 1. Хэшировать входящий token (тем же алгоритмом)
    // 2. Искать в sessions WHERE token_hash = хэш AND expires_at > now()
    // 3. Если найдено и expires_at в будущем — вернуть Session (с user_id)
    // 4. Если не найдено или expired — вернуть ошибку (401)
}

// DestroySession удаляет сессию из БД (logout)
func (sm *SessionManager) DestroySession(ctx context.Context, sessionID uuid.UUID) error {
    // DELETE FROM sessions WHERE id = sessionID
}

// GetUserFromToken — вспомогательный: прочитать user_id из валидной сессии
func (sm *SessionManager) GetUserFromToken(ctx context.Context, token string) (*uuid.UUID, error) {
    // валидировать, вернуть user_id если валидна
}
```

> **Про хэширование:** AC-6.9 явно требует хранение token_hash (не самого токена), что предотвращает утечку полного токена при компрометации БД. Используем `sha256` (стандартная `crypto/sha256`) или PBKDF2 (как для password_hash) — выбрать более лёгкий вариант (sha256 достаточно для одноразового хэша, не юзер-пароля).

---

## 3. Обновление `internal/auth`

Текущий код (по аудиту) использует старый механизм сессий. Нужно:

- Удалить зависимости на старый `secureookie` / подписанную cookie (если есть).
- Добавить инъекцию `SessionManager` в `AuthService`.
- Метод `AuthService.Login(ctx, email, password)` теперь:
  - Проверяет email/password как раньше.
  - Вместо `c.SetCookie(...)` с подписью: вызывает `sm.CreateSession(ctx, userID, 24*time.Hour)`.
  - Возвращает token (или передаёт его в middleware для установки cookie).
- Метод `AuthService.Logout(ctx, token)`:
  - Получает session_id из token.
  - Вызывает `sm.DestroySession(ctx, sessionID)`.

---

## 4. Обновление HTTP handlers

### 4.1. `POST /login` handler

```go
// текущее поведение: вход, установка подписанной cookie, 204 No Content
// новое поведение: вход, вызов CreateSession, установка HttpOnly cookie с token, 204 No Content

func (a *API) Login(c *gin.Context) {
    var req struct { Email string; Password string }
    c.BindJSON(&req)

    userID, err := a.auth.ValidatePassword(c.Request.Context(), req.Email, req.Password)
    if err != nil {
        c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
        return
    }

    // создать serverside-сессию
    token, err := a.sessionManager.CreateSession(c.Request.Context(), userID, 24*time.Hour)
    if err != nil {
        c.JSON(http.StatusInternalServerError, ...)
        return
    }

    // установить как HttpOnly cookie (не открыта для JS, передача по HTTPS только)
    c.SetCookie(
        "session_token",
        token.Value,
        int(24 * 3600),  // MaxAge в секундах
        "/",
        "api.videcdn.net",  // domain
        true,  // Secure (HTTPS)
        true,  // HttpOnly
    )

    c.JSON(http.StatusNoContent, nil)
}
```

### 4.2. `POST /logout` handler (если не существует — создать)

```go
func (a *API) Logout(c *gin.Context) {
    token, err := c.Cookie("session_token")
    if err != nil {
        c.JSON(http.StatusNoContent, nil)  // даже если не залогинен, просто ок
        return
    }

    a.sessionManager.DestroySession(c.Request.Context(), /* нужно session_id из token */ )

    c.SetCookie("session_token", "", -1, "/", "", true, true)  // удалить cookie
    c.JSON(http.StatusNoContent, nil)
}
```

> Проблема: CreateSession возвращает Token с Value, но нам нужно session.ID для DestroySession. Либо возвращать оба (Token и session_id), либо хранить session_id где-то.

---

## 5. Обновление middleware

### 5.1. `middleware.RequireAuth` (или как это называется сейчас)

Вместо проверки подписи cookie:

```go
func RequireAuth(sm *SessionManager) gin.HandlerFunc {
    return func(c *gin.Context) {
        token, err := c.Cookie("session_token")
        if err != nil {
            c.AbortWithStatus(http.StatusUnauthorized)
            return
        }

        session, err := sm.ValidateToken(c.Request.Context(), token)
        if err != nil {
            c.AbortWithStatus(http.StatusUnauthorized)
            return
        }

        // сохранить user_id в контекст (как раньше)
        c.Set("user_id", session.UserID)
        c.Next()
    }
}
```

---

## 6. Acceptance-проверка

| # | Проверка | Статус |
|---|---|---|
| 1 | Таблица `sessions` заполняется при логине | — |
| 2 | POST /login → 204, cookie `session_token` установлена | — |
| 3 | Cookie `session_token` содержит token (не hash) | — |
| 4 | GET запрос с валидной cookie работает (RequireAuth пропускает) | — |
| 5 | GET запрос с поддельной/истекшей cookie → 401 | — |
| 6 | POST /logout → 204, cookie удалена, запись удалена из sessions | — |
| 7 | Token expires через N часов (проверить через прямой INSERT в sessions с истекшим expires_at) | — |
| 8 | Нет утечек: token_hash в БД, не сам token | — |
| 9 | go test ./internal/session, ./internal/auth, ./internal/api → все зелёные | — |
| 10 | Smoke-тест: login → POST /clients (protected endpoint) → 201 | — |

---

## 7. Регрессия-чеклист

- [ ] `POST /login` с верными кредами → 204 + cookie
- [ ] `POST /login` с неверными кредами → 401, no cookie
- [ ] `POST /clients` (protected) с валидной cookie → работает как раньше
- [ ] `POST /clients` без cookie → 401
- [ ] Старые code.SetCookie/c.GetCookie на подписанной cookie **полностью удалены** (не осталось legacy-кода)

---

## 8. Отчёт

Сформировать таблицу по п.6 (все пункты acceptance + результат), затем:
- Перечень всех изменённых файлов
- Какие пакеты/модули зависят от SessionManager (audit: где используется RequireAuth)
- Smoke-тест результаты
- Любые UNKNOWN детали (например, если timeZone для expires_at выбирался произвольно)

Отчёт сохранить в **`ai_from_local/P2.2_Serverside_Sessions_Report.md`** и закоммитить:
```bash
git add ai_from_local/P2.2_Serverside_Sessions_Report.md
git add internal/session/*.go internal/auth/*.go internal/api/login.go
git add internal/middleware/*.go  (если RequireAuth там)
git commit -m "P2.2: Serverside sessions (token_hash in DB, replace stateless cookie)"
git push origin master
```

Вывод на экран оставить как есть, но файл обязателен.

---

## 9. Важные детали

- **Timezone:** `expires_at` в sessions — это `TIMESTAMPTZ` (UTC), сравнивать с `now()` (в коде: `time.Now().UTC()`).
- **Token формат:** случайные 32 байта, закодировать base64 или hex (главное — однозначно декодируется и воспроизводится для хэширования).
- **Hash алгоритм:** SHA256 (`crypto/sha256`), просто: `sha256.Sum256(token)`, результат hex-закодировать для хранения в VARCHAR.
- **Cookie флаги:** `HttpOnly=true` (не доступна JS), `Secure=true` (только HTTPS), `SameSite=Lax` (по умолчанию в Go).
- **Expiry проверка:** `where expires_at > now()` — в коде и SQL.
- **DestroySession должен быть идемпотентным:** если сессия уже удалена, не ошибка.
