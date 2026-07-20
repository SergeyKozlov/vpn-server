package api

import (
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"time"

	"vpn-api/internal/clients"
)

type createClientRequest struct {
	ExpiresAt         *time.Time `json:"expires_at"`
	TrafficLimitBytes int64      `json:"traffic_limit_bytes"`
	LimitIP           int        `json:"limit_ip"`
}

type createClientResponse struct {
	ID                int64      `json:"id"`
	Email             string     `json:"email"`
	VlessUUID         string     `json:"vless_uuid"`
	Hysteria2Username string     `json:"hysteria2_username"`
	Hysteria2Password string     `json:"hysteria2_password"`
	SubID             string     `json:"sub_id"`
	TrafficLimitBytes int64      `json:"traffic_limit_bytes"`
	LimitIP           int        `json:"limit_ip"`
	ExpiresAt         *time.Time `json:"expires_at,omitempty"`
	CreatedAt         time.Time  `json:"created_at"`
}

func createClientHandler(svc *clients.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, 4096)

		var req createClientRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil && !errors.Is(err, io.EOF) {
			writeJSONError(w, http.StatusBadRequest, "invalid request body")
			return
		}

		c, err := svc.Create(r.Context(), clients.CreateParams{
			ExpiresAt:         req.ExpiresAt,
			TrafficLimitBytes: req.TrafficLimitBytes,
			LimitIP:           req.LimitIP,
		})
		if err != nil {
			if errors.Is(err, clients.ErrInvalidParams) {
				writeJSONError(w, http.StatusBadRequest, err.Error())
				return
			}
			log.Printf("create client: %v", err)
			writeJSONError(w, http.StatusInternalServerError, "failed to create client")
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(createClientResponse{
			ID:                c.ID,
			Email:             c.Email,
			VlessUUID:         c.VlessUUID,
			Hysteria2Username: c.Hysteria2Username,
			Hysteria2Password: c.Hysteria2Password,
			SubID:             c.SubID,
			TrafficLimitBytes: c.TrafficLimitBytes,
			LimitIP:           c.LimitIP,
			ExpiresAt:         c.ExpiresAt,
			CreatedAt:         c.CreatedAt,
		})
	}
}

func writeJSONError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}
