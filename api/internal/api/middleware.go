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
func RequireAuth(sm *session.SessionManager) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			cookie, err := r.Cookie(sessionCookieName)
			if err != nil {
				writeJSONError(w, http.StatusUnauthorized, "authentication required")
				return
			}

			userID, err := sm.GetUserFromToken(r.Context(), cookie.Value)
			if err != nil {
				writeJSONError(w, http.StatusUnauthorized, "authentication required")
				return
			}

			ctx := context.WithValue(r.Context(), userIDContextKey, *userID)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
