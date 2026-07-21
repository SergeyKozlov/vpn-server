package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"vpn-api/internal/session"
	"vpn-api/internal/testutil"
)

func testMiddlewarePool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	testutil.LoadEnv()
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
		if _, err := pool.Exec(context.Background(), "DELETE FROM admin_sessions"); err != nil {
			t.Fatalf("clean admin_sessions table: %v", err)
		}
		if _, err := pool.Exec(context.Background(), "DELETE FROM admins"); err != nil {
			t.Fatalf("clean admins table: %v", err)
		}
		if _, err := pool.Exec(context.Background(), "DELETE FROM sessions"); err != nil {
			t.Fatalf("clean sessions table: %v", err)
		}
		if _, err := pool.Exec(context.Background(), "DELETE FROM users"); err != nil {
			t.Fatalf("clean users table: %v", err)
		}
	}
	clean()
	t.Cleanup(clean)

	return pool
}

func testAdminID(t *testing.T, pool *pgxpool.Pool) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	err := pool.QueryRow(context.Background(),
		`INSERT INTO admins (username, password_hash) VALUES ($1, 'x') RETURNING id`,
		uuid.NewString()).Scan(&id)
	if err != nil {
		t.Fatalf("insert test admin: %v", err)
	}
	return id
}

func TestRequireAuthNoCookie(t *testing.T) {
	pool := testMiddlewarePool(t)
	sm := session.NewSessionManager(pool, "admin_sessions")
	handler := RequireAuth(sm)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
	pool := testMiddlewarePool(t)
	sm := session.NewSessionManager(pool, "admin_sessions")
	handler := RequireAuth(sm)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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

func TestRequireAuthExpiredCookie(t *testing.T) {
	pool := testMiddlewarePool(t)
	sm := session.NewSessionManager(pool, "admin_sessions")
	userID := testAdminID(t, pool)

	token, err := sm.CreateSession(context.Background(), userID, -time.Minute)
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}

	handler := RequireAuth(sm)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: token.Value})
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

func TestRequireAuthValidCookie(t *testing.T) {
	pool := testMiddlewarePool(t)
	sm := session.NewSessionManager(pool, "admin_sessions")
	userID := testAdminID(t, pool)

	token, err := sm.CreateSession(context.Background(), userID, session.DefaultTTL)
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}

	called := false
	handler := RequireAuth(sm)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		if got := r.Context().Value(userIDContextKey); got != userID {
			t.Errorf("context userID = %v, want %v", got, userID)
		}
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: token.Value, Expires: token.ExpiresAt})
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	if !called {
		t.Fatal("wrapped handler was not called")
	}
}
