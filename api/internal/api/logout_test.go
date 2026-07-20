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
