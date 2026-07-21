package api

import (
	"log"
	"net/http"
	"time"

	"vpn-api/internal/auth"
)

func logoutHandler(svc *auth.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie(sessionCookieName)
		if err == nil {
			if err := svc.Logout(r.Context(), cookie.Value); err != nil {
				log.Printf("logout: %v", err)
				writeJSONError(w, http.StatusInternalServerError, "logout failed")
				return
			}
		}

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
