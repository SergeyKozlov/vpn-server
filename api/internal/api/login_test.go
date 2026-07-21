package api

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"vpn-api/internal/auth"
	"vpn-api/internal/password"
	"vpn-api/internal/session"
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
		if _, err := pool.Exec(context.Background(), "DELETE FROM sessions"); err != nil {
			t.Fatalf("clean sessions table: %v", err)
		}
		if _, err := pool.Exec(context.Background(), "DELETE FROM admins"); err != nil {
			t.Fatalf("clean admins table: %v", err)
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
	if _, err := pool.Exec(context.Background(), `INSERT INTO admins (username, password_hash) VALUES ($1, $2)`, username, hash); err != nil {
		t.Fatalf("insert test user: %v", err)
	}
}

func TestLoginSuccess(t *testing.T) {
	pool := testAuthPool(t)
	createTestUser(t, pool, "admin", "correct-password")

	sm := session.NewManager(pool)
	svc := auth.NewService(pool, sm)
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

	svc := auth.NewService(pool, session.NewManager(pool))
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

	svc := auth.NewService(pool, session.NewManager(pool))
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
	svc := auth.NewService(pool, session.NewManager(pool))
	handler := loginHandler(svc, newLoginRateLimiter(loginRateLimit, loginRateWindow))

	req := httptest.NewRequest(http.MethodPost, "/login", bytes.NewBufferString(`{not json`))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
}

func TestLoginBodyTooLarge(t *testing.T) {
	pool := testAuthPool(t)
	svc := auth.NewService(pool, session.NewManager(pool))
	handler := loginHandler(svc, newLoginRateLimiter(loginRateLimit, loginRateWindow))

	body := bytes.NewBufferString(`{"username":"admin","password":"` + strings.Repeat("a", 1<<20) + `"}`)
	req := httptest.NewRequest(http.MethodPost, "/login", body)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d, body: %s", rec.Code, http.StatusBadRequest, rec.Body.String())
	}
}

func TestLoginRateLimitExceeded(t *testing.T) {
	pool := testAuthPool(t)
	createTestUser(t, pool, "admin", "correct-password")

	svc := auth.NewService(pool, session.NewManager(pool))
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
