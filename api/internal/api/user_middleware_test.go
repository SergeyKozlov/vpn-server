package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"vpn-api/internal/session"
	"vpn-api/internal/users"
)

func TestRequireUserAuthNoCookie(t *testing.T) {
	pool := testMiddlewarePool(t)
	sm := session.NewSessionManager(pool, "sessions")
	handler := RequireUserAuth(sm)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

func TestRequireUserAuthInvalidCookie(t *testing.T) {
	pool := testMiddlewarePool(t)
	sm := session.NewSessionManager(pool, "sessions")
	handler := RequireUserAuth(sm)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: clientSessionCookieName, Value: "garbage"})
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

func TestRequireUserAuthExpiredCookie(t *testing.T) {
	pool := testMiddlewarePool(t)
	sm := session.NewSessionManager(pool, "sessions")
	usersSvc := users.NewService(pool, sm)

	u, err := usersSvc.Register(context.Background(), "expired-cookie@example.com", "correct-password")
	if err != nil {
		t.Fatalf("Register: %v", err)
	}

	token, err := sm.CreateSession(context.Background(), u.ID, -time.Minute)
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}

	handler := RequireUserAuth(sm)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: clientSessionCookieName, Value: token.Value})
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

func TestRequireUserAuthValidCookie(t *testing.T) {
	pool := testMiddlewarePool(t)
	sm := session.NewSessionManager(pool, "sessions")
	usersSvc := users.NewService(pool, sm)

	u, err := usersSvc.Register(context.Background(), "valid-cookie@example.com", "correct-password")
	if err != nil {
		t.Fatalf("Register: %v", err)
	}

	token, _, err := usersSvc.Login(context.Background(), "valid-cookie@example.com", "correct-password")
	if err != nil {
		t.Fatalf("Login: %v", err)
	}

	called := false
	handler := RequireUserAuth(sm)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		if got := r.Context().Value(clientUserIDContextKey); got != u.ID {
			t.Errorf("context clientUserID = %v, want %v", got, u.ID)
		}
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: clientSessionCookieName, Value: token})
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	if !called {
		t.Fatal("wrapped handler was not called")
	}
}
