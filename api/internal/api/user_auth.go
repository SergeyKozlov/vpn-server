package api

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"time"

	"github.com/google/uuid"

	"vpn-api/internal/users"
)

type registerRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type registerResponse struct {
	ID          string     `json:"id"`
	Email       string     `json:"email"`
	Status      string     `json:"status"`
	TrialEndsAt *time.Time `json:"trial_ends_at"`
}

func registerHandler(svc *users.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, 4096)

		var req registerRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSONError(w, http.StatusBadRequest, "invalid request body")
			return
		}

		u, err := svc.Register(r.Context(), req.Email, req.Password)
		if err != nil {
			switch {
			case errors.Is(err, users.ErrInvalidInput):
				writeJSONError(w, http.StatusBadRequest, "invalid email or password")
			case errors.Is(err, users.ErrEmailTaken):
				writeJSONError(w, http.StatusConflict, "email already registered")
			default:
				log.Printf("register: %v", err)
				writeJSONError(w, http.StatusInternalServerError, "registration failed")
			}
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(registerResponse{
			ID:          u.ID.String(),
			Email:       u.Email,
			Status:      u.Status,
			TrialEndsAt: u.TrialEndsAt,
		})
	}
}

type userLoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

func userLoginHandler(svc *users.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, 4096)

		var req userLoginRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSONError(w, http.StatusBadRequest, "invalid request body")
			return
		}
		if req.Email == "" || req.Password == "" {
			writeJSONError(w, http.StatusBadRequest, "email and password are required")
			return
		}

		token, expiresAt, err := svc.Login(r.Context(), req.Email, req.Password)
		if err != nil {
			if errors.Is(err, users.ErrInvalidCredentials) {
				writeJSONError(w, http.StatusUnauthorized, "invalid email or password")
				return
			}
			log.Printf("user login: %v", err)
			writeJSONError(w, http.StatusInternalServerError, "login failed")
			return
		}

		http.SetCookie(w, &http.Cookie{
			Name:     clientSessionCookieName,
			Value:    token,
			Path:     "/",
			Expires:  expiresAt,
			HttpOnly: true,
			Secure:   true,
			SameSite: http.SameSiteLaxMode,
		})
		w.WriteHeader(http.StatusNoContent)
	}
}

func userLogoutHandler(svc *users.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie(clientSessionCookieName)
		if err == nil {
			if err := svc.Logout(r.Context(), cookie.Value); err != nil {
				log.Printf("user logout: %v", err)
				writeJSONError(w, http.StatusInternalServerError, "logout failed")
				return
			}
		}

		http.SetCookie(w, &http.Cookie{
			Name:     clientSessionCookieName,
			Value:    "",
			Path:     "/",
			Expires:  time.Unix(0, 0),
			MaxAge:   -1,
			HttpOnly: true,
			Secure:   true,
			SameSite: http.SameSiteLaxMode,
		})
		w.WriteHeader(http.StatusNoContent)
	}
}

type meResponse struct {
	ID          string     `json:"id"`
	Email       string     `json:"email"`
	Status      string     `json:"status"`
	TrialEndsAt *time.Time `json:"trial_ends_at"`
}

func meHandler(svc *users.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		userID := r.Context().Value(clientUserIDContextKey).(uuid.UUID)

		u, err := svc.GetByID(r.Context(), userID)
		if err != nil {
			if errors.Is(err, users.ErrNotFound) {
				writeJSONError(w, http.StatusUnauthorized, "authentication required")
				return
			}
			log.Printf("me: %v", err)
			writeJSONError(w, http.StatusInternalServerError, "failed to load user")
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(meResponse{
			ID:          u.ID.String(),
			Email:       u.Email,
			Status:      u.EffectiveStatus(time.Now().UTC()),
			TrialEndsAt: u.TrialEndsAt,
		})
	}
}
