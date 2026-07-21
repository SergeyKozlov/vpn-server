// Package api wires HTTP routes to the underlying services. Handlers stay
// thin — request/response translation only, business logic lives in the
// service packages they call.
package api

import (
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/jackc/pgx/v5/pgxpool"

	"vpn-api/internal/auth"
	"vpn-api/internal/clients"
	"vpn-api/internal/session"
	"vpn-api/internal/users"
)

// NewRouter wires the two independent auth circuits: admins (adminSessions,
// cookie vpn_session) protect panel/provisioning routes; users
// (userSessions, cookie vpn_user_session) protect the client-facing
// /api/v1/auth/* routes. See TZ P2.3 for why these must stay independent.
func NewRouter(pool *pgxpool.Pool, clientsSvc *clients.Service, authSvc *auth.Service, adminSessions *session.SessionManager, usersSvc *users.Service, userSessions *session.SessionManager) chi.Router {
	r := chi.NewRouter()
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)

	limiter := newLoginRateLimiter(loginRateLimit, loginRateWindow)

	r.Get("/healthz", healthzHandler(pool))
	r.Post("/login", loginHandler(authSvc, limiter))
	r.Post("/logout", logoutHandler(authSvc))

	r.Group(func(r chi.Router) {
		r.Use(RequireAuth(adminSessions))
		r.Post("/clients", createClientHandler(clientsSvc))
	})

	r.Post("/api/v1/auth/register", registerHandler(usersSvc))
	r.Post("/api/v1/auth/login", userLoginHandler(usersSvc))
	r.Post("/api/v1/auth/logout", userLogoutHandler(usersSvc))

	r.Group(func(r chi.Router) {
		r.Use(RequireUserAuth(userSessions))
		r.Get("/api/v1/auth/me", meHandler(usersSvc))
	})

	return r
}
