# Login / Auth Middleware Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a login endpoint, stateless signed-cookie sessions, and auth middleware that protects `POST /clients` (and any future mutating routes), per `docs/superpowers/specs/2026-07-19-login-auth-middleware-design.md`.

**Architecture:** A new `internal/session` package signs/verifies opaque HMAC-SHA256 cookie tokens (no DB session table). A new `internal/auth` package authenticates against the existing `users` table and issues those tokens. `internal/api` gains `/login` (with an in-memory per-IP rate limiter) and `/logout` handlers plus a `RequireAuth` middleware wrapping `POST /clients`. A new `cmd/createadmin` CLI seeds the first admin row, since there is no public registration endpoint.

**Tech Stack:** Go 1.26.5, stdlib `crypto/hmac`/`crypto/sha256` (no new dependency), existing `argon2id` password package, `pgx/v5`, `chi/v5`.

## Global Constraints

- Session mechanism: stateless signed cookie, HMAC-SHA256, no session table, TTL = 24 hours.
- First admin creation: dedicated CLI command only, no public registration endpoint.
- Login rate limiting: in-memory limiter, 5 attempts/minute per client IP, resets on process restart, not shared across instances (Phase 1 is single-instance).
- CSRF defense: `SameSite=Strict` cookie attribute only — no CSRF token scheme.
- Login failures (unknown username vs wrong password) return the identical generic `401` — no user enumeration.
- Cookie flags: `HttpOnly`, `Secure`, `SameSite=Strict`, `Path=/`.
- New required env var `SESSION_SIGNING_KEY`: base64-encoded, must decode to exactly 32 bytes, hard-fail at startup like `APP_ENC_KEY`/`DATABASE_URL`.
- No new DB migration — `users` table (`id BIGSERIAL`, `username TEXT UNIQUE`, `password_hash TEXT`) already has everything needed.
- Follow existing repo conventions: package doc comment on the first line of each new package's primary file; `DecodeKey`-style base64 key helpers (see `internal/crypto/crypto.go`); generic `writeJSONError` responses with no leaked detail; `t.Skip` on unset `DATABASE_URL` for integration tests (see `internal/clients/service_test.go`, `internal/api/clients_test.go`).
- All commands below run from `/root/vpn/api` unless stated otherwise. Integration tests need `DATABASE_URL` set and the `vpn-postgres` container running (`docker compose up -d` from `/root/vpn`).

---

### Task 1: `internal/session` — signed cookie tokens

**Files:**
- Create: `api/internal/session/session.go`
- Test: `api/internal/session/session_test.go`

**Interfaces:**
- Consumes: nothing (stdlib only).
- Produces: `const session.KeySize = 32`, `const session.TTL = 24 * time.Hour`, `var session.ErrInvalidToken error`, `session.NewSigner(key []byte) (*session.Signer, error)`, `(*session.Signer).Sign(userID int64) (token string, expiresAt time.Time)`, `(*session.Signer).Verify(token string) (int64, error)`, `session.DecodeKey(s string) ([]byte, error)`.

- [ ] **Step 1: Write the failing test**

Create `api/internal/session/session_test.go`:

```go
package session

import (
	"bytes"
	"encoding/base64"
	"testing"
	"time"
)

func testKey() []byte {
	return bytes.Repeat([]byte("k"), KeySize)
}

func TestSignVerifyRoundTrip(t *testing.T) {
	signer, err := NewSigner(testKey())
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}

	token, expiresAt := signer.Sign(42)
	if token == "" {
		t.Fatal("expected non-empty token")
	}
	if time.Until(expiresAt) > TTL || time.Until(expiresAt) < TTL-time.Second {
		t.Fatalf("expiresAt = %v, want ~%v from now", expiresAt, TTL)
	}

	userID, err := signer.Verify(token)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if userID != 42 {
		t.Fatalf("userID = %d, want 42", userID)
	}
}

func TestVerifyRejectsTamperedSignature(t *testing.T) {
	signer, err := NewSigner(testKey())
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}

	token, _ := signer.Sign(42)
	tampered := token[:len(token)-1] + "x"

	if _, err := signer.Verify(tampered); err != ErrInvalidToken {
		t.Fatalf("Verify(tampered) err = %v, want %v", err, ErrInvalidToken)
	}
}

func TestVerifyRejectsWrongKey(t *testing.T) {
	signerA, err := NewSigner(testKey())
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	signerB, err := NewSigner(bytes.Repeat([]byte("z"), KeySize))
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}

	token, _ := signerA.Sign(42)

	if _, err := signerB.Verify(token); err != ErrInvalidToken {
		t.Fatalf("Verify with wrong key err = %v, want %v", err, ErrInvalidToken)
	}
}

func TestVerifyRejectsExpiredToken(t *testing.T) {
	signer, err := NewSigner(testKey())
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}

	payload := encodePayload(42, time.Now().Add(-time.Minute))
	token := encodeToken(payload, signer.sign(payload))

	if _, err := signer.Verify(token); err != ErrInvalidToken {
		t.Fatalf("Verify(expired) err = %v, want %v", err, ErrInvalidToken)
	}
}

func TestVerifyRejectsMalformedToken(t *testing.T) {
	signer, err := NewSigner(testKey())
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}

	for _, bad := range []string{"", "no-dot-here", "a.b.c", "!!!.!!!"} {
		if _, err := signer.Verify(bad); err != ErrInvalidToken {
			t.Fatalf("Verify(%q) err = %v, want %v", bad, err, ErrInvalidToken)
		}
	}
}

func TestNewSignerRejectsBadKeyLength(t *testing.T) {
	if _, err := NewSigner([]byte("too-short")); err == nil {
		t.Fatal("expected error for short key")
	}
}

func TestDecodeKeyRoundTrip(t *testing.T) {
	// Any 32-byte key round-trips through DecodeKey after being base64-encoded.
	key := testKey()
	encoded := base64.StdEncoding.EncodeToString(key)

	decoded, err := DecodeKey(encoded)
	if err != nil {
		t.Fatalf("DecodeKey: %v", err)
	}
	if !bytes.Equal(decoded, key) {
		t.Fatalf("decoded = %v, want %v", decoded, key)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/session/... -v`
Expected: FAIL — `package session: no Go files` or undefined symbols (package doesn't exist yet).

- [ ] **Step 3: Write the implementation**

Create `api/internal/session/session.go`:

```go
// Package session implements stateless, HMAC-signed session tokens carried
// in a cookie: no session table, no server-side revocation before expiry.
package session

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"time"
)

const KeySize = 32

// TTL is how long a signed token remains valid after Sign.
const TTL = 24 * time.Hour

// ErrInvalidToken covers every verification failure — malformed token, bad
// signature, or expiry — callers don't need to distinguish which.
var ErrInvalidToken = errors.New("invalid or expired session token")

type Signer struct {
	key []byte
}

func NewSigner(key []byte) (*Signer, error) {
	if len(key) != KeySize {
		return nil, fmt.Errorf("key must be %d bytes, got %d", KeySize, len(key))
	}
	return &Signer{key: key}, nil
}

// Sign returns an opaque token string encoding userID and an expiry TTL from
// now, plus that same expiry for the caller to use as the cookie's Expires.
func (s *Signer) Sign(userID int64) (token string, expiresAt time.Time) {
	expiresAt = time.Now().Add(TTL)
	payload := encodePayload(userID, expiresAt)
	return encodeToken(payload, s.sign(payload)), expiresAt
}

// Verify checks the token's signature and expiry, returning the embedded
// userID on success.
func (s *Signer) Verify(token string) (int64, error) {
	parts := strings.SplitN(token, ".", 2)
	if len(parts) != 2 {
		return 0, ErrInvalidToken
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return 0, ErrInvalidToken
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return 0, ErrInvalidToken
	}

	if !hmac.Equal(sig, s.sign(payload)) {
		return 0, ErrInvalidToken
	}

	userID, expiresAt, err := decodePayload(payload)
	if err != nil {
		return 0, ErrInvalidToken
	}
	if time.Now().After(expiresAt) {
		return 0, ErrInvalidToken
	}

	return userID, nil
}

func (s *Signer) sign(payload []byte) []byte {
	mac := hmac.New(sha256.New, s.key)
	mac.Write(payload)
	return mac.Sum(nil)
}

func encodeToken(payload, sig []byte) string {
	return base64.RawURLEncoding.EncodeToString(payload) + "." + base64.RawURLEncoding.EncodeToString(sig)
}

// encodePayload packs userID and expiresAt (unix seconds) as two
// big-endian int64s.
func encodePayload(userID int64, expiresAt time.Time) []byte {
	buf := make([]byte, 16)
	binary.BigEndian.PutUint64(buf[0:8], uint64(userID))
	binary.BigEndian.PutUint64(buf[8:16], uint64(expiresAt.Unix()))
	return buf
}

func decodePayload(payload []byte) (userID int64, expiresAt time.Time, err error) {
	if len(payload) != 16 {
		return 0, time.Time{}, errors.New("malformed payload")
	}
	userID = int64(binary.BigEndian.Uint64(payload[0:8]))
	expiresAt = time.Unix(int64(binary.BigEndian.Uint64(payload[8:16])), 0)
	return userID, expiresAt, nil
}

// DecodeKey decodes a base64-encoded signing key, e.g. from the
// SESSION_SIGNING_KEY environment variable.
func DecodeKey(s string) ([]byte, error) {
	key, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("decode key: %w", err)
	}
	if len(key) != KeySize {
		return nil, fmt.Errorf("key must decode to %d bytes, got %d", KeySize, len(key))
	}
	return key, nil
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/session/... -v`
Expected: PASS, all `Test*` functions listed as `--- PASS`.

- [ ] **Step 5: Commit**

```bash
cd /root/vpn && git add api/internal/session/
git commit -m "feat: add stateless signed-cookie session tokens"
```

---

### Task 2: `internal/auth` — login business logic

**Files:**
- Create: `api/internal/auth/auth.go`
- Test: `api/internal/auth/auth_test.go`

**Interfaces:**
- Consumes: `session.Signer` (Task 1) — specifically `(*session.Signer).Sign(userID int64) (string, time.Time)`; `password.Verify(password, hash string) (bool, error)` and `password.Hash(password string) (string, error)` (existing, `api/internal/password/password.go`); `*pgxpool.Pool` (existing).
- Produces: `var auth.ErrInvalidCredentials error`, `auth.NewService(pool *pgxpool.Pool, signer *session.Signer) *auth.Service`, `(*auth.Service).Login(ctx context.Context, username, password string) (token string, expiresAt time.Time, err error)`.

- [ ] **Step 1: Write the failing test**

Create `api/internal/auth/auth_test.go`:

```go
package auth

import (
	"context"
	"crypto/rand"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"vpn-api/internal/password"
	"vpn-api/internal/session"
)

func testPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		t.Skip("DATABASE_URL not set; skipping integration test")
	}

	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatalf("connect pool: %v", err)
	}
	t.Cleanup(pool.Close)

	clean := func() {
		if _, err := pool.Exec(context.Background(), "DELETE FROM users"); err != nil {
			t.Fatalf("clean users table: %v", err)
		}
	}
	clean()
	t.Cleanup(clean)

	return pool
}

func testSigner(t *testing.T) *session.Signer {
	t.Helper()
	key := make([]byte, session.KeySize)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("generate key: %v", err)
	}
	signer, err := session.NewSigner(key)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	return signer
}

func createUser(t *testing.T, pool *pgxpool.Pool, username, plaintextPassword string) int64 {
	t.Helper()
	hash, err := password.Hash(plaintextPassword)
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}

	var id int64
	err = pool.QueryRow(context.Background(),
		`INSERT INTO users (username, password_hash) VALUES ($1, $2) RETURNING id`,
		username, hash).Scan(&id)
	if err != nil {
		t.Fatalf("insert user: %v", err)
	}
	return id
}

func TestLoginSuccess(t *testing.T) {
	pool := testPool(t)
	wantID := createUser(t, pool, "admin", "correct-password")

	signer := testSigner(t)
	svc := NewService(pool, signer)

	token, expiresAt, err := svc.Login(context.Background(), "admin", "correct-password")
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	if expiresAt.Before(time.Now()) {
		t.Fatalf("expiresAt = %v, want a future time", expiresAt)
	}

	gotID, err := signer.Verify(token)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if gotID != wantID {
		t.Fatalf("userID = %d, want %d", gotID, wantID)
	}
}

func TestLoginWrongPassword(t *testing.T) {
	pool := testPool(t)
	createUser(t, pool, "admin", "correct-password")
	svc := NewService(pool, testSigner(t))

	_, _, err := svc.Login(context.Background(), "admin", "wrong-password")
	if !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("err = %v, want %v", err, ErrInvalidCredentials)
	}
}

func TestLoginUnknownUsername(t *testing.T) {
	pool := testPool(t)
	svc := NewService(pool, testSigner(t))

	_, _, err := svc.Login(context.Background(), "ghost", "whatever")
	if !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("err = %v, want %v", err, ErrInvalidCredentials)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/auth/... -v`
Expected: FAIL — `package auth: no Go files`.

- [ ] **Step 3: Write the implementation**

Create `api/internal/auth/auth.go`. The dummy hash below was generated once with `password.Hash("dummy-password-for-timing-only")` — it's a real, validly-formatted Argon2id hash for an unrelated password, used only so `password.Verify` does its full expensive computation on an unknown username (timing-safe against username enumeration):

```go
// Package auth authenticates panel admins against the users table and
// issues signed session tokens. HTTP concerns (cookies, rate limiting) live
// in internal/api; this package is pure business logic.
package auth

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"vpn-api/internal/password"
	"vpn-api/internal/session"
)

// ErrInvalidCredentials covers both an unknown username and a wrong
// password — callers must not distinguish the two in responses (no user
// enumeration).
var ErrInvalidCredentials = errors.New("invalid username or password")

// dummyHash is a real Argon2id hash of an unrelated, fixed password. It's
// compared against on an unknown username so Login takes roughly the same
// time whether the username exists or not.
const dummyHash = "$argon2id$v=19$m=32768,t=3,p=1$j/NqoamR1wG3VSwtXr1Afw$XlfEmrHn0bJqxkmu693XxeGqnoOrFd0/K/XqRgxRiE0"

type Service struct {
	pool   *pgxpool.Pool
	signer *session.Signer
}

func NewService(pool *pgxpool.Pool, signer *session.Signer) *Service {
	return &Service{pool: pool, signer: signer}
}

func (s *Service) Login(ctx context.Context, username, plaintextPassword string) (token string, expiresAt time.Time, err error) {
	var userID int64
	var hash string
	err = s.pool.QueryRow(ctx, `SELECT id, password_hash FROM users WHERE username = $1`, username).Scan(&userID, &hash)
	if errors.Is(err, pgx.ErrNoRows) {
		_, _ = password.Verify(plaintextPassword, dummyHash)
		return "", time.Time{}, ErrInvalidCredentials
	}
	if err != nil {
		return "", time.Time{}, fmt.Errorf("query user: %w", err)
	}

	ok, err := password.Verify(plaintextPassword, hash)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("verify password: %w", err)
	}
	if !ok {
		return "", time.Time{}, ErrInvalidCredentials
	}

	token, expiresAt = s.signer.Sign(userID)
	return token, expiresAt, nil
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `DATABASE_URL=$(grep DATABASE_URL /root/vpn/.env | cut -d= -f2-) go test ./internal/auth/... -v`
Expected: PASS for `TestLoginSuccess`, `TestLoginWrongPassword`, `TestLoginUnknownUsername`.

- [ ] **Step 5: Commit**

```bash
cd /root/vpn && git add api/internal/auth/
git commit -m "feat: add auth.Service.Login against the users table"
```

---

### Task 3: `internal/api` — in-memory login rate limiter

**Files:**
- Create: `api/internal/api/ratelimit.go`
- Test: `api/internal/api/ratelimit_test.go`

**Interfaces:**
- Consumes: nothing new.
- Produces: `newLoginRateLimiter(limit int, window time.Duration) *loginRateLimiter`, `(*loginRateLimiter).allow(key string) bool`, `clientIP(r *http.Request) string`. All unexported — consumed only within `internal/api` (Task 5's `login.go`).

- [ ] **Step 1: Write the failing test**

Create `api/internal/api/ratelimit_test.go`:

```go
package api

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestLoginRateLimiterAllowsWithinLimit(t *testing.T) {
	limiter := newLoginRateLimiter(3, time.Minute)

	for i := 0; i < 3; i++ {
		if !limiter.allow("1.2.3.4") {
			t.Fatalf("attempt %d: expected allow", i+1)
		}
	}
}

func TestLoginRateLimiterBlocksOverLimit(t *testing.T) {
	limiter := newLoginRateLimiter(2, time.Minute)

	limiter.allow("1.2.3.4")
	limiter.allow("1.2.3.4")
	if limiter.allow("1.2.3.4") {
		t.Fatal("expected block on 3rd attempt")
	}
}

func TestLoginRateLimiterTracksKeysIndependently(t *testing.T) {
	limiter := newLoginRateLimiter(1, time.Minute)

	if !limiter.allow("1.2.3.4") {
		t.Fatal("expected allow for first key")
	}
	if !limiter.allow("5.6.7.8") {
		t.Fatal("expected allow for a different key")
	}
}

func TestLoginRateLimiterResetsAfterWindow(t *testing.T) {
	limiter := newLoginRateLimiter(1, 10*time.Millisecond)

	if !limiter.allow("1.2.3.4") {
		t.Fatal("expected allow for first attempt")
	}
	time.Sleep(20 * time.Millisecond)
	if !limiter.allow("1.2.3.4") {
		t.Fatal("expected allow after window reset")
	}
}

func TestClientIPSplitsPort(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "203.0.113.5:54321"

	if got := clientIP(req); got != "203.0.113.5" {
		t.Fatalf("clientIP = %q, want %q", got, "203.0.113.5")
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/api/... -run TestLoginRateLimiter -v`
Expected: FAIL — `undefined: newLoginRateLimiter`.

- [ ] **Step 3: Write the implementation**

Create `api/internal/api/ratelimit.go`:

```go
package api

import (
	"net"
	"net/http"
	"sync"
	"time"
)

// loginRateLimiter is a simple fixed-window counter keyed by client IP,
// scoped to the /login route. It's in-memory only — state resets on
// process restart and isn't shared across multiple API instances, which is
// fine for Phase 1's single-instance deployment.
type loginRateLimiter struct {
	mu       sync.Mutex
	limit    int
	window   time.Duration
	attempts map[string]*attemptWindow
}

type attemptWindow struct {
	count      int
	windowFrom time.Time
}

func newLoginRateLimiter(limit int, window time.Duration) *loginRateLimiter {
	return &loginRateLimiter{
		limit:    limit,
		window:   window,
		attempts: make(map[string]*attemptWindow),
	}
}

// allow reports whether key (the client IP) may make another attempt right
// now, incrementing its counter if so.
func (l *loginRateLimiter) allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()
	w, ok := l.attempts[key]
	if !ok || now.Sub(w.windowFrom) > l.window {
		l.attempts[key] = &attemptWindow{count: 1, windowFrom: now}
		return true
	}

	if w.count >= l.limit {
		return false
	}
	w.count++
	return true
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/api/... -run 'TestLoginRateLimiter|TestClientIP' -v`
Expected: PASS for all five tests.

- [ ] **Step 5: Commit**

```bash
cd /root/vpn && git add api/internal/api/ratelimit.go api/internal/api/ratelimit_test.go
git commit -m "feat: add in-memory per-IP login rate limiter"
```

---

### Task 4: `internal/api` — `RequireAuth` middleware

**Files:**
- Create: `api/internal/api/middleware.go`
- Test: `api/internal/api/middleware_test.go`

**Interfaces:**
- Consumes: `session.Signer` (Task 1) — `(*session.Signer).Verify(token string) (int64, error)`; `writeJSONError` (existing, `api/internal/api/clients.go`).
- Produces: `const sessionCookieName = "vpn_session"`, `RequireAuth(signer *session.Signer) func(http.Handler) http.Handler`, and a test helper `testSigner(t *testing.T) *session.Signer` that Task 5 and Task 6's tests also reuse (same package, no re-declaration needed).

- [ ] **Step 1: Write the failing test**

Create `api/internal/api/middleware_test.go`:

```go
package api

import (
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"testing"

	"vpn-api/internal/session"
)

func testSigner(t *testing.T) *session.Signer {
	t.Helper()
	key := make([]byte, session.KeySize)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("generate key: %v", err)
	}
	signer, err := session.NewSigner(key)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	return signer
}

func TestRequireAuthNoCookie(t *testing.T) {
	signer := testSigner(t)
	handler := RequireAuth(signer)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

func TestRequireAuthInvalidCookie(t *testing.T) {
	signer := testSigner(t)
	handler := RequireAuth(signer)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: "garbage"})
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

func TestRequireAuthValidCookie(t *testing.T) {
	signer := testSigner(t)
	token, expiresAt := signer.Sign(42)

	called := false
	handler := RequireAuth(signer)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: token, Expires: expiresAt})
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	if !called {
		t.Fatal("wrapped handler was not called")
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/api/... -run TestRequireAuth -v`
Expected: FAIL — `undefined: RequireAuth`, `undefined: sessionCookieName`.

- [ ] **Step 3: Write the implementation**

Create `api/internal/api/middleware.go`:

```go
package api

import (
	"context"
	"net/http"

	"vpn-api/internal/session"
)

// sessionCookieName is the cookie both /login sets and RequireAuth reads.
const sessionCookieName = "vpn_session"

type contextKey string

const userIDContextKey contextKey = "userID"

// RequireAuth wraps handlers that need an authenticated admin session. On
// failure it returns 401 with no detail — callers can't distinguish a
// missing cookie from an expired or tampered one.
func RequireAuth(signer *session.Signer) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			cookie, err := r.Cookie(sessionCookieName)
			if err != nil {
				writeJSONError(w, http.StatusUnauthorized, "authentication required")
				return
			}

			userID, err := signer.Verify(cookie.Value)
			if err != nil {
				writeJSONError(w, http.StatusUnauthorized, "authentication required")
				return
			}

			ctx := context.WithValue(r.Context(), userIDContextKey, userID)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/api/... -run TestRequireAuth -v`
Expected: PASS for all three tests.

- [ ] **Step 5: Commit**

```bash
cd /root/vpn && git add api/internal/api/middleware.go api/internal/api/middleware_test.go
git commit -m "feat: add RequireAuth session-cookie middleware"
```

---

### Task 5: `internal/api` — `/login` and `/logout` handlers

**Files:**
- Create: `api/internal/api/login.go`
- Create: `api/internal/api/logout.go`
- Test: `api/internal/api/login_test.go`
- Test: `api/internal/api/logout_test.go`

**Interfaces:**
- Consumes: `auth.Service` (Task 2) — `(*auth.Service).Login(ctx, username, password string) (string, time.Time, error)`, `auth.ErrInvalidCredentials`; `loginRateLimiter`/`clientIP` (Task 3); `sessionCookieName` (Task 4); `writeJSONError` (existing).
- Produces: `loginHandler(svc *auth.Service, limiter *loginRateLimiter) http.HandlerFunc`, `logoutHandler() http.HandlerFunc`, `const loginRateLimit = 5`, `const loginRateWindow = time.Minute` (consumed by Task 6's `router.go`).

- [ ] **Step 1: Write the failing tests**

Create `api/internal/api/login_test.go`:

```go
package api

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"vpn-api/internal/auth"
	"vpn-api/internal/password"
)

func testAuthPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		t.Skip("DATABASE_URL not set; skipping integration test")
	}

	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatalf("connect pool: %v", err)
	}
	t.Cleanup(pool.Close)

	clean := func() {
		if _, err := pool.Exec(context.Background(), "DELETE FROM users"); err != nil {
			t.Fatalf("clean users table: %v", err)
		}
	}
	clean()
	t.Cleanup(clean)

	return pool
}

func createTestUser(t *testing.T, pool *pgxpool.Pool, username, plaintextPassword string) {
	t.Helper()
	hash, err := password.Hash(plaintextPassword)
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}
	if _, err := pool.Exec(context.Background(), `INSERT INTO users (username, password_hash) VALUES ($1, $2)`, username, hash); err != nil {
		t.Fatalf("insert test user: %v", err)
	}
}

func TestLoginSuccess(t *testing.T) {
	pool := testAuthPool(t)
	createTestUser(t, pool, "admin", "correct-password")

	signer := testSigner(t)
	svc := auth.NewService(pool, signer)
	handler := loginHandler(svc, newLoginRateLimiter(loginRateLimit, loginRateWindow))

	body := bytes.NewBufferString(`{"username":"admin","password":"correct-password"}`)
	req := httptest.NewRequest(http.MethodPost, "/login", body)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d, body: %s", rec.Code, http.StatusNoContent, rec.Body.String())
	}

	cookies := rec.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Name != sessionCookieName || cookies[0].Value == "" {
		t.Fatalf("expected session cookie set, got %v", cookies)
	}
}

func TestLoginWrongPassword(t *testing.T) {
	pool := testAuthPool(t)
	createTestUser(t, pool, "admin", "correct-password")

	svc := auth.NewService(pool, testSigner(t))
	handler := loginHandler(svc, newLoginRateLimiter(loginRateLimit, loginRateWindow))

	body := bytes.NewBufferString(`{"username":"admin","password":"wrong-password"}`)
	req := httptest.NewRequest(http.MethodPost, "/login", body)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

func TestLoginUnknownUsername(t *testing.T) {
	pool := testAuthPool(t)

	svc := auth.NewService(pool, testSigner(t))
	handler := loginHandler(svc, newLoginRateLimiter(loginRateLimit, loginRateWindow))

	body := bytes.NewBufferString(`{"username":"ghost","password":"whatever"}`)
	req := httptest.NewRequest(http.MethodPost, "/login", body)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

func TestLoginMalformedBody(t *testing.T) {
	pool := testAuthPool(t)
	svc := auth.NewService(pool, testSigner(t))
	handler := loginHandler(svc, newLoginRateLimiter(loginRateLimit, loginRateWindow))

	req := httptest.NewRequest(http.MethodPost, "/login", bytes.NewBufferString(`{not json`))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
}

func TestLoginRateLimitExceeded(t *testing.T) {
	pool := testAuthPool(t)
	createTestUser(t, pool, "admin", "correct-password")

	svc := auth.NewService(pool, testSigner(t))
	handler := loginHandler(svc, newLoginRateLimiter(2, time.Minute))

	attempt := func() int {
		body := bytes.NewBufferString(`{"username":"admin","password":"wrong-password"}`)
		req := httptest.NewRequest(http.MethodPost, "/login", body)
		req.RemoteAddr = "203.0.113.1:12345"
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec.Code
	}

	if code := attempt(); code != http.StatusUnauthorized {
		t.Fatalf("attempt 1: status = %d, want %d", code, http.StatusUnauthorized)
	}
	if code := attempt(); code != http.StatusUnauthorized {
		t.Fatalf("attempt 2: status = %d, want %d", code, http.StatusUnauthorized)
	}
	if code := attempt(); code != http.StatusTooManyRequests {
		t.Fatalf("attempt 3: status = %d, want %d", code, http.StatusTooManyRequests)
	}
}
```

Create `api/internal/api/logout_test.go`:

```go
package api

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestLogoutClearsCookie(t *testing.T) {
	handler := logoutHandler()

	req := httptest.NewRequest(http.MethodPost, "/logout", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusNoContent)
	}

	cookies := rec.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Name != sessionCookieName || cookies[0].MaxAge >= 0 {
		t.Fatalf("expected an expired session cookie, got %v", cookies)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/api/... -run 'TestLogin|TestLogout' -v`
Expected: FAIL — `undefined: loginHandler`, `undefined: logoutHandler`, `undefined: loginRateLimit`.

- [ ] **Step 3: Write the implementation**

Create `api/internal/api/login.go`:

```go
package api

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"time"

	"vpn-api/internal/auth"
)

const (
	loginRateLimit  = 5
	loginRateWindow = time.Minute
)

type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func loginHandler(svc *auth.Service, limiter *loginRateLimiter) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !limiter.allow(clientIP(r)) {
			writeJSONError(w, http.StatusTooManyRequests, "too many login attempts, try again later")
			return
		}

		var req loginRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSONError(w, http.StatusBadRequest, "invalid request body")
			return
		}
		if req.Username == "" || req.Password == "" {
			writeJSONError(w, http.StatusBadRequest, "username and password are required")
			return
		}

		token, expiresAt, err := svc.Login(r.Context(), req.Username, req.Password)
		if err != nil {
			if errors.Is(err, auth.ErrInvalidCredentials) {
				writeJSONError(w, http.StatusUnauthorized, "invalid username or password")
				return
			}
			log.Printf("login: %v", err)
			writeJSONError(w, http.StatusInternalServerError, "login failed")
			return
		}

		http.SetCookie(w, &http.Cookie{
			Name:     sessionCookieName,
			Value:    token,
			Path:     "/",
			Expires:  expiresAt,
			HttpOnly: true,
			Secure:   true,
			SameSite: http.SameSiteStrictMode,
		})
		w.WriteHeader(http.StatusNoContent)
	}
}
```

Create `api/internal/api/logout.go`:

```go
package api

import (
	"net/http"
	"time"
)

func logoutHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{
			Name:     sessionCookieName,
			Value:    "",
			Path:     "/",
			Expires:  time.Unix(0, 0),
			MaxAge:   -1,
			HttpOnly: true,
			Secure:   true,
			SameSite: http.SameSiteStrictMode,
		})
		w.WriteHeader(http.StatusNoContent)
	}
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `DATABASE_URL=$(grep DATABASE_URL /root/vpn/.env | cut -d= -f2-) go test ./internal/api/... -run 'TestLogin|TestLogout' -v`
Expected: PASS for all six tests (`TestLoginSuccess`, `TestLoginWrongPassword`, `TestLoginUnknownUsername`, `TestLoginMalformedBody`, `TestLoginRateLimitExceeded`, `TestLogoutClearsCookie`).

- [ ] **Step 5: Commit**

```bash
cd /root/vpn && git add api/internal/api/login.go api/internal/api/logout.go api/internal/api/login_test.go api/internal/api/logout_test.go
git commit -m "feat: add /login and /logout handlers"
```

---

### Task 6: Wire auth into the router; protect `POST /clients`

**Files:**
- Modify: `api/internal/api/router.go`
- Modify: `api/internal/api/clients_test.go`

**Interfaces:**
- Consumes: `auth.Service`, `session.Signer`, `loginHandler`, `logoutHandler`, `RequireAuth`, `newLoginRateLimiter`, `loginRateLimit`, `loginRateWindow` (all prior tasks).
- Produces: `api.NewRouter(pool *pgxpool.Pool, clientsSvc *clients.Service, authSvc *auth.Service, signer *session.Signer) chi.Router` — **signature changed**, Task 7's `main.go` must pass the two new arguments.

- [ ] **Step 1: Update `router.go`**

Modify `api/internal/api/router.go` — replace its entire contents:

```go
// Package api wires HTTP routes to the underlying services. Handlers stay
// thin — request/response translation only, business logic lives in the
// service packages they call.
package api

import (
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/jackc/pgx/v5/pgxpool"

	"vpn-api/internal/auth"
	"vpn-api/internal/clients"
	"vpn-api/internal/session"
)

func NewRouter(pool *pgxpool.Pool, clientsSvc *clients.Service, authSvc *auth.Service, signer *session.Signer) chi.Router {
	r := chi.NewRouter()
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)

	limiter := newLoginRateLimiter(loginRateLimit, loginRateWindow)

	r.Get("/healthz", healthzHandler(pool))
	r.Post("/login", loginHandler(authSvc, limiter))
	r.Post("/logout", logoutHandler())

	r.Group(func(r chi.Router) {
		r.Use(RequireAuth(signer))
		r.Post("/clients", createClientHandler(clientsSvc))
	})

	return r
}
```

- [ ] **Step 2: Update `clients_test.go`'s `testRouter` and every call site**

Modify `api/internal/api/clients_test.go`. First, update the imports block:

```go
import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"vpn-api/internal/auth"
	"vpn-api/internal/clients"
	appcrypto "vpn-api/internal/crypto"
	"vpn-api/internal/session"
	"vpn-api/internal/xui"
)
```

Replace the `testRouter` function so it also builds a signer and auth service, and returns the signer so tests can mint a valid cookie without a real HTTP round trip through `/login` (login itself is already covered by Task 5's tests):

```go
func testRouter(t *testing.T) (http.Handler, *session.Signer) {
	t.Helper()

	pool := testPool(t)

	key := make([]byte, appcrypto.KeySize)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("generate key: %v", err)
	}
	cryptor, err := appcrypto.NewAESGCM(key)
	if err != nil {
		t.Fatalf("NewAESGCM: %v", err)
	}

	configPath := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(configPath, []byte("auth:\n  type: userpass\n  userpass: {}\n"), 0o600); err != nil {
		t.Fatalf("write hysteria config: %v", err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]any{"success": true})
	}))
	t.Cleanup(srv.Close)

	panel, err := xui.NewPanel(srv.URL, "test-token")
	if err != nil {
		t.Fatalf("NewPanel: %v", err)
	}

	clientsSvc := clients.NewService(pool, panel, cryptor, 1, configPath, "true")

	signer := testSigner(t)
	authSvc := auth.NewService(pool, signer)

	return NewRouter(pool, clientsSvc, authSvc, signer), signer
}

func authCookie(signer *session.Signer) *http.Cookie {
	token, expiresAt := signer.Sign(1)
	return &http.Cookie{Name: sessionCookieName, Value: token, Expires: expiresAt}
}
```

Update every existing test to destructure both return values and attach the cookie to its request. `TestCreateClientEndpointSuccess`:

```go
func TestCreateClientEndpointSuccess(t *testing.T) {
	router, signer := testRouter(t)

	body := bytes.NewBufferString(`{"traffic_limit_bytes": 1073741824, "limit_ip": 3}`)
	req := httptest.NewRequest(http.MethodPost, "/clients", body)
	req.AddCookie(authCookie(signer))
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want %d, body: %s", rec.Code, http.StatusCreated, rec.Body.String())
	}

	var resp map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	for _, field := range []string{"id", "email", "vless_uuid", "hysteria2_username", "hysteria2_password", "sub_id"} {
		if _, ok := resp[field]; !ok {
			t.Errorf("response missing field %q: %v", field, resp)
		}
	}
	if resp["limit_ip"].(float64) != 3 {
		t.Errorf("limit_ip = %v, want 3", resp["limit_ip"])
	}
}
```

`TestCreateClientEndpointEmptyBodyUsesDefaults`:

```go
func TestCreateClientEndpointEmptyBodyUsesDefaults(t *testing.T) {
	router, signer := testRouter(t)

	req := httptest.NewRequest(http.MethodPost, "/clients", nil)
	req.AddCookie(authCookie(signer))
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want %d, body: %s", rec.Code, http.StatusCreated, rec.Body.String())
	}
}
```

`TestCreateClientEndpointInvalidJSON`:

```go
func TestCreateClientEndpointInvalidJSON(t *testing.T) {
	router, signer := testRouter(t)

	req := httptest.NewRequest(http.MethodPost, "/clients", bytes.NewBufferString(`{not json`))
	req.AddCookie(authCookie(signer))
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
}
```

`TestCreateClientEndpointNegativeTrafficLimit`:

```go
func TestCreateClientEndpointNegativeTrafficLimit(t *testing.T) {
	router, signer := testRouter(t)

	req := httptest.NewRequest(http.MethodPost, "/clients", bytes.NewBufferString(`{"traffic_limit_bytes": -1}`))
	req.AddCookie(authCookie(signer))
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d, body: %s", rec.Code, http.StatusBadRequest, rec.Body.String())
	}
}
```

Add one new test proving the route is actually protected:

```go
func TestCreateClientEndpointRequiresAuth(t *testing.T) {
	router, _ := testRouter(t)

	req := httptest.NewRequest(http.MethodPost, "/clients", bytes.NewBufferString(`{}`))
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}
```

- [ ] **Step 3: Run the full `internal/api` test suite**

Run: `DATABASE_URL=$(grep DATABASE_URL /root/vpn/.env | cut -d= -f2-) go test ./internal/api/... -v`
Expected: PASS for every test in the package, including the five `TestCreateClientEndpoint*` tests and all Task 3/4/5 tests.

- [ ] **Step 4: Commit**

```bash
cd /root/vpn && git add api/internal/api/router.go api/internal/api/clients_test.go
git commit -m "feat: protect POST /clients behind RequireAuth"
```

---

### Task 7: Config and `main.go` wiring — `SESSION_SIGNING_KEY`

**Files:**
- Modify: `api/internal/config/config.go`
- Modify: `api/cmd/api/main.go`

**Interfaces:**
- Consumes: `session.DecodeKey(s string) ([]byte, error)`, `session.NewSigner(key []byte) (*session.Signer, error)`, `auth.NewService(pool, signer) *auth.Service` (all prior tasks); `api.NewRouter`'s new signature (Task 6).
- Produces: `config.Config.SessionSigningKey string` field, consumed only by `main.go`.

- [ ] **Step 1: Add `SessionSigningKey` to `Config`**

Modify `api/internal/config/config.go`. Add the field to the struct:

```go
type Config struct {
	Port        string
	DatabaseURL string

	EncryptionKey     string // base64-encoded 32-byte AES-256 key
	SessionSigningKey string // base64-encoded 32-byte HMAC key for session cookies

	XUIBaseURL   string // must include the panel's webBasePath
	XUIAPIToken  string
	XUIInboundID int

	HysteriaConfigPath    string
	HysteriaReloadCommand string
}
```

Add the `requireEnv` call in `Load`, right after `encryptionKey`:

```go
	encryptionKey, err := requireEnv("APP_ENC_KEY")
	if err != nil {
		return nil, err
	}

	sessionSigningKey, err := requireEnv("SESSION_SIGNING_KEY")
	if err != nil {
		return nil, err
	}
```

And add the field to the returned `&Config{...}` literal:

```go
	return &Config{
		Port:                  port,
		DatabaseURL:           databaseURL,
		EncryptionKey:         encryptionKey,
		SessionSigningKey:     sessionSigningKey,
		XUIBaseURL:            xuiBaseURL,
		XUIAPIToken:           xuiAPIToken,
		XUIInboundID:          xuiInboundID,
		HysteriaConfigPath:    hysteriaConfigPath,
		HysteriaReloadCommand: hysteriaReloadCommand,
	}, nil
```

- [ ] **Step 2: Wire it into `main.go`**

Modify `api/cmd/api/main.go`. Add two imports:

```go
	"vpn-api/internal/api"
	"vpn-api/internal/auth"
	"vpn-api/internal/clients"
	"vpn-api/internal/config"
	"vpn-api/internal/crypto"
	"vpn-api/internal/database"
	"vpn-api/internal/session"
	"vpn-api/internal/xui"
```

Insert signer/auth construction right after the existing `panel, err := xui.NewPanel(...)` block and before `clientsSvc := clients.NewService(...)`:

```go
	sessionKey, err := session.DecodeKey(cfg.SessionSigningKey)
	if err != nil {
		return err
	}
	signer, err := session.NewSigner(sessionKey)
	if err != nil {
		return err
	}

	authSvc := auth.NewService(pool, signer)
```

Update the router construction line:

```go
	r := api.NewRouter(pool, clientsSvc, authSvc, signer)
```

- [ ] **Step 3: Verify the module builds**

Run: `go build ./...`
Expected: no output, exit code 0.

- [ ] **Step 4: Run the full test suite (unit tests only, no DB needed for this task)**

Run: `go vet ./...`
Expected: no output, exit code 0.

- [ ] **Step 5: Commit**

```bash
cd /root/vpn && git add api/internal/config/config.go api/cmd/api/main.go
git commit -m "feat: wire SESSION_SIGNING_KEY and auth.Service into main"
```

---

### Task 8: `cmd/createadmin` — one-shot admin creation CLI

**Files:**
- Create: `api/cmd/createadmin/main.go`

**Interfaces:**
- Consumes: `password.Hash(password string) (string, error)` (existing); `pgconn.PgError` (from the already-required `github.com/jackc/pgx/v5` module, subpackage `github.com/jackc/pgx/v5/pgconn` — no `go.mod` change needed).
- Produces: a standalone binary, no importable symbols.

- [ ] **Step 1: Write the command**

Create `api/cmd/createadmin/main.go`:

```go
// Command createadmin inserts a single admin row into the users table. Run
// once, manually, on the server — there is no public registration
// endpoint. Requires the same DATABASE_URL as the api service, and expects
// migrations to have already been applied (run the api service at least
// once first).
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"vpn-api/internal/password"
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	username := flag.String("u", "", "admin username (required)")
	pw := flag.String("p", "", "admin password (required)")
	flag.Parse()

	if *username == "" || *pw == "" {
		return errors.New("both -u and -p are required")
	}

	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		return errors.New("DATABASE_URL is required")
	}

	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return fmt.Errorf("connect: %w", err)
	}
	defer pool.Close()

	hash, err := password.Hash(*pw)
	if err != nil {
		return fmt.Errorf("hash password: %w", err)
	}

	_, err = pool.Exec(ctx, `INSERT INTO users (username, password_hash) VALUES ($1, $2)`, *username, hash)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return fmt.Errorf("user %q already exists", *username)
		}
		return fmt.Errorf("insert admin: %w", err)
	}

	fmt.Printf("created admin user %q\n", *username)
	return nil
}
```

No automated test for this command — per the approved design, it's a one-shot operational tool, not a code path exercised by the running service, and is instead verified manually in Task 9.

- [ ] **Step 2: Verify it builds**

Run: `go build ./...`
Expected: no output, exit code 0.

- [ ] **Step 3: Commit**

```bash
cd /root/vpn && git add api/cmd/createadmin/main.go
git commit -m "feat: add createadmin CLI for one-shot admin bootstrap"
```

---

### Task 9: Env config docs + end-to-end manual verification

**Files:**
- Modify: `.env.example`
- Modify: `.env`

**Interfaces:** none (documentation/config only).

- [ ] **Step 1: Add `SESSION_SIGNING_KEY` to `.env.example`**

Modify `/root/vpn/.env.example`, adding this block after the existing `APP_ENC_KEY` line:

```
# 32 random bytes, base64-encoded, e.g. `openssl rand -base64 32`. Signs
# session cookies issued by POST /login.
SESSION_SIGNING_KEY=changeme
```

- [ ] **Step 2: Generate a real key and add it to `.env`**

Run: `openssl rand -base64 32`

Take the printed value and add a line to `/root/vpn/.env` (do not commit this file — it's already in `.gitignore`):

```
SESSION_SIGNING_KEY=<paste the generated value here>
```

- [ ] **Step 3: Full test suite with real Postgres**

Run (from `/root/vpn/api`): `DATABASE_URL=$(grep DATABASE_URL /root/vpn/.env | cut -d= -f2-) go test ./... -v 2>&1 | tail -60`
Expected: `ok` for every package with tests (`internal/api`, `internal/auth`, `internal/clients`, `internal/crypto`, `internal/hysteria`, `internal/password`, `internal/session`, `internal/xui`), no `FAIL` lines.

- [ ] **Step 4: Manual end-to-end smoke test**

This exercises `createadmin` → `/login` → cookie → `/clients` against the real `vpn-postgres` container (already running via `docker compose up -d`), with a mock 3x-ui and Hysteria2 config standing in — the same throwaway-mock pattern used for prior smoke tests, so nothing touches the real panel.

```bash
cd /root/vpn/api
export DATABASE_URL=$(grep DATABASE_URL /root/vpn/.env | cut -d= -f2-)

# 1. Create a throwaway admin.
go run ./cmd/createadmin -u smoketest -p smoketest-password-123

# 2. Start a mock 3x-ui on :19191 (background) and a scratch Hysteria2 config.
python3 -c "
import http.server, json
class H(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        self.send_response(200)
        self.send_header('Content-Type','application/json')
        self.end_headers()
        self.wfile.write(json.dumps({'success': True}).encode())
http.server.HTTPServer(('127.0.0.1', 19191), H).serve_forever()
" &
MOCK_PID=$!
sleep 1
echo "auth:
  type: userpass
  userpass: {}" > /tmp/smoketest-hysteria.yaml

# 3. Start the real API against the mock, on :18080.
PORT=18080 XUI_BASE_URL=http://127.0.0.1:19191 XUI_API_TOKEN=smoketest-token \
  HYSTERIA_CONFIG_PATH=/tmp/smoketest-hysteria.yaml HYSTERIA_RELOAD_COMMAND=true \
  go run ./cmd/api &
API_PID=$!
sleep 2

# 4. Log in, capture the cookie, hit the protected route with and without it.
curl -sS -c /tmp/smoketest-cookies.txt -o /dev/null -w '%{http_code}\n' \
  -X POST http://127.0.0.1:18080/login -d '{"username":"smoketest","password":"smoketest-password-123"}'
# expect: 204

curl -sS -o /dev/null -w '%{http_code}\n' -X POST http://127.0.0.1:18080/clients -d '{}'
# expect: 401 (no cookie)

curl -sS -b /tmp/smoketest-cookies.txt -o /dev/null -w '%{http_code}\n' \
  -X POST http://127.0.0.1:18080/clients -d '{}'
# expect: 201

# 5. Clean up.
kill $API_PID $MOCK_PID
psql "$DATABASE_URL" -c "DELETE FROM clients; DELETE FROM users WHERE username = 'smoketest';"
rm -f /tmp/smoketest-hysteria.yaml /tmp/smoketest-cookies.txt
```

Expected output: `204`, then `401`, then `201`, confirming login issues a working session cookie and `POST /clients` is genuinely gated by it.

- [ ] **Step 5: Commit the env doc changes**

```bash
cd /root/vpn && git add .env.example
git commit -m "docs: document SESSION_SIGNING_KEY in .env.example"
```

(`.env` itself is gitignored — nothing to commit there.)

---

## Self-Review Notes

- **Spec coverage:** stateless signed cookie (Task 1), auth against `users` (Task 2), rate limiting (Task 3), middleware (Task 4), login/logout endpoints (Task 5), route protection (Task 6), `SESSION_SIGNING_KEY` config (Task 7), CLI admin bootstrap (Task 8), env docs + smoke test (Task 9) — every design decision has a task.
- **Type consistency checked:** `session.Signer.Sign`/`Verify` signatures match between Task 1's implementation and every consumer (Task 2, Task 4, Task 6 test helpers). `loginRateLimit`/`loginRateWindow` constants defined once in Task 5, referenced (not redefined) in Task 6 and Task 9. `sessionCookieName` defined once in Task 4, referenced everywhere else.
- **No placeholders remain** — the one draft placeholder in Task 1's test-writing step is explicitly replaced with real code in the same step, not left dangling.
