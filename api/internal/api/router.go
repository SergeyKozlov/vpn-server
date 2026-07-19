// Package api wires HTTP routes to the underlying services. Handlers stay
// thin — request/response translation only, business logic lives in the
// service packages they call.
package api

import (
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/jackc/pgx/v5/pgxpool"

	"vpn-api/internal/clients"
)

func NewRouter(pool *pgxpool.Pool, clientsSvc *clients.Service) chi.Router {
	r := chi.NewRouter()
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)

	r.Get("/healthz", healthzHandler(pool))
	r.Post("/clients", createClientHandler(clientsSvc))

	return r
}
