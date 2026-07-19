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
