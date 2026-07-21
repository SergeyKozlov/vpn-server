package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"vpn-api/internal/auth"
	"vpn-api/internal/password"
	"vpn-api/internal/session"
)

func TestLogoutClearsCookieNoSession(t *testing.T) {
	pool := testMiddlewarePool(t)
	svc := auth.NewService(pool, session.NewSessionManager(pool, "admin_sessions"))
	handler := logoutHandler(svc)

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

func TestLogoutDestroysSession(t *testing.T) {
	pool := testMiddlewarePool(t)
	sm := session.NewSessionManager(pool, "admin_sessions")
	svc := auth.NewService(pool, sm)

	hash, err := password.Hash("correct-password")
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}
	if _, err := pool.Exec(context.Background(),
		`INSERT INTO admins (username, password_hash) VALUES ($1, $2)`, "admin", hash); err != nil {
		t.Fatalf("insert test admin: %v", err)
	}

	token, expiresAt, err := svc.Login(context.Background(), "admin", "correct-password")
	if err != nil {
		t.Fatalf("Login: %v", err)
	}

	handler := logoutHandler(svc)
	req := httptest.NewRequest(http.MethodPost, "/logout", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: token, Expires: expiresAt})
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusNoContent)
	}

	cookies := rec.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Name != sessionCookieName || cookies[0].MaxAge >= 0 {
		t.Fatalf("expected an expired session cookie, got %v", cookies)
	}

	if _, err := sm.ValidateToken(context.Background(), token); err != session.ErrInvalidToken {
		t.Fatalf("session still valid after logout: err = %v, want %v", err, session.ErrInvalidToken)
	}
}
