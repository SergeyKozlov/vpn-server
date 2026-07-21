package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"vpn-api/internal/session"
	"vpn-api/internal/users"
)

func TestRegisterEndpointSuccess(t *testing.T) {
	pool := testPool(t)
	svc := users.NewService(pool, session.NewSessionManager(pool, "sessions"))
	handler := registerHandler(svc)

	body := bytes.NewBufferString(`{"email":"new@example.com","password":"correct-password"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/register", body)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want %d, body: %s", rec.Code, http.StatusCreated, rec.Body.String())
	}

	var resp registerResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if resp.Email != "new@example.com" {
		t.Errorf("email = %q, want %q", resp.Email, "new@example.com")
	}
	if resp.Status != "trial" {
		t.Errorf("status = %q, want %q", resp.Status, "trial")
	}
	if resp.TrialEndsAt == nil {
		t.Error("trial_ends_at is nil")
	}
	if resp.ID == "" {
		t.Error("id is empty")
	}
}

func TestRegisterEndpointDuplicateEmail(t *testing.T) {
	pool := testPool(t)
	svc := users.NewService(pool, session.NewSessionManager(pool, "sessions"))
	handler := registerHandler(svc)

	attempt := func() int {
		body := bytes.NewBufferString(`{"email":"dup-endpoint@example.com","password":"correct-password"}`)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/register", body)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec.Code
	}

	if code := attempt(); code != http.StatusCreated {
		t.Fatalf("attempt 1: status = %d, want %d", code, http.StatusCreated)
	}
	if code := attempt(); code != http.StatusConflict {
		t.Fatalf("attempt 2: status = %d, want %d", code, http.StatusConflict)
	}
}

func TestRegisterEndpointInvalidInput(t *testing.T) {
	pool := testPool(t)
	svc := users.NewService(pool, session.NewSessionManager(pool, "sessions"))
	handler := registerHandler(svc)

	for _, body := range []string{
		`{"email":"","password":"correct-password"}`,
		`{"email":"bad@example.com","password":"short"}`,
		`{not json`,
	} {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/register", bytes.NewBufferString(body))
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("body %q: status = %d, want %d", body, rec.Code, http.StatusBadRequest)
		}
	}
}

func TestUserLoginEndpointSuccess(t *testing.T) {
	pool := testPool(t)
	sm := session.NewSessionManager(pool, "sessions")
	svc := users.NewService(pool, sm)

	if _, err := svc.Register(context.Background(), "login-endpoint@example.com", "correct-password"); err != nil {
		t.Fatalf("Register: %v", err)
	}

	handler := userLoginHandler(svc)
	body := bytes.NewBufferString(`{"email":"login-endpoint@example.com","password":"correct-password"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", body)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d, body: %s", rec.Code, http.StatusNoContent, rec.Body.String())
	}

	cookies := rec.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Name != clientSessionCookieName || cookies[0].Value == "" {
		t.Fatalf("expected client session cookie set, got %v", cookies)
	}
}

func TestUserLoginEndpointWrongPassword(t *testing.T) {
	pool := testPool(t)
	sm := session.NewSessionManager(pool, "sessions")
	svc := users.NewService(pool, sm)

	if _, err := svc.Register(context.Background(), "wrongpass-endpoint@example.com", "correct-password"); err != nil {
		t.Fatalf("Register: %v", err)
	}

	handler := userLoginHandler(svc)
	body := bytes.NewBufferString(`{"email":"wrongpass-endpoint@example.com","password":"nope"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", body)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

func TestMeEndpointShowsLazyExpiredTrial(t *testing.T) {
	pool := testPool(t)
	sm := session.NewSessionManager(pool, "sessions")
	svc := users.NewService(pool, sm)

	u, err := svc.Register(context.Background(), "me-expired@example.com", "correct-password")
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	if _, err := pool.Exec(context.Background(),
		"UPDATE users SET trial_ends_at = now() - interval '1 day' WHERE id = $1", u.ID); err != nil {
		t.Fatalf("update trial_ends_at: %v", err)
	}

	token, _, err := svc.Login(context.Background(), "me-expired@example.com", "correct-password")
	if err != nil {
		t.Fatalf("Login: %v", err)
	}

	handler := RequireUserAuth(sm)(meHandler(svc))
	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/me", nil)
	req.AddCookie(&http.Cookie{Name: clientSessionCookieName, Value: token})
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d, body: %s", rec.Code, http.StatusOK, rec.Body.String())
	}

	var resp meResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if resp.Status != "expired" {
		t.Errorf("status = %q, want %q", resp.Status, "expired")
	}
}

func TestMeEndpointRejectsAdminCookie(t *testing.T) {
	router, adminCookie, _ := testRouter(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/me", nil)
	req.AddCookie(adminCookie)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

func TestUserLogoutEndpointIsIdempotent(t *testing.T) {
	pool := testPool(t)
	sm := session.NewSessionManager(pool, "sessions")
	svc := users.NewService(pool, sm)

	handler := userLogoutHandler(svc)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/logout", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusNoContent)
	}

	cookies := rec.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Name != clientSessionCookieName || cookies[0].MaxAge >= 0 {
		t.Fatalf("expected an expired client session cookie, got %v", cookies)
	}
}

func TestUserLogoutEndpointDestroysSession(t *testing.T) {
	pool := testPool(t)
	sm := session.NewSessionManager(pool, "sessions")
	svc := users.NewService(pool, sm)

	if _, err := svc.Register(context.Background(), "logout-endpoint@example.com", "correct-password"); err != nil {
		t.Fatalf("Register: %v", err)
	}
	token, _, err := svc.Login(context.Background(), "logout-endpoint@example.com", "correct-password")
	if err != nil {
		t.Fatalf("Login: %v", err)
	}

	handler := userLogoutHandler(svc)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/logout", nil)
	req.AddCookie(&http.Cookie{Name: clientSessionCookieName, Value: token})
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusNoContent)
	}

	if _, err := sm.ValidateToken(context.Background(), token); err != session.ErrInvalidToken {
		t.Fatalf("session still valid after logout: err = %v, want %v", err, session.ErrInvalidToken)
	}
}
