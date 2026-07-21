package api

import (
	"context"
	"net/http"

	"vpn-api/internal/session"
)

// clientSessionCookieName is the cookie the client /login sets and
// RequireUserAuth reads. Deliberately distinct from sessionCookieName
// (admin) so an admin cookie can never authenticate a client request or
// vice versa.
const clientSessionCookieName = "vpn_user_session"

const clientUserIDContextKey contextKey = "clientUserID"

// RequireUserAuth wraps handlers that need an authenticated client
// session. Mirrors RequireAuth but validates against the client
// SessionManager (sessions table) and stores the user ID under a context
// key separate from the admin circuit's.
func RequireUserAuth(sm *session.SessionManager) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			cookie, err := r.Cookie(clientSessionCookieName)
			if err != nil {
				writeJSONError(w, http.StatusUnauthorized, "authentication required")
				return
			}

			userID, err := sm.GetUserFromToken(r.Context(), cookie.Value)
			if err != nil {
				writeJSONError(w, http.StatusUnauthorized, "authentication required")
				return
			}

			ctx := context.WithValue(r.Context(), clientUserIDContextKey, *userID)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
