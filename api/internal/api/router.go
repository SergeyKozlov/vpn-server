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
)

func NewRouter(pool *pgxpool.Pool, clientsSvc *clients.Service, authSvc *auth.Service, sm *session.SessionManager) chi.Router {
	r := chi.NewRouter()
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)

	limiter := newLoginRateLimiter(loginRateLimit, loginRateWindow)

	r.Get("/healthz", healthzHandler(pool))
	r.Post("/login", loginHandler(authSvc, limiter))
	r.Post("/logout", logoutHandler(authSvc))

	r.Group(func(r chi.Router) {
		r.Use(RequireAuth(sm))
		r.Post("/clients", createClientHandler(clientsSvc))
	})

	return r
}
