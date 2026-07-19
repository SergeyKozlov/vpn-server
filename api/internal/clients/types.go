package clients

import "time"

// CreateParams are the admin-supplied parameters for a new client. Identity
// (email/UUID/username/subId) and secrets are generated server-side.
type CreateParams struct {
	ExpiresAt         *time.Time // nil = never expires
	TrafficLimitBytes int64      // 0 = unlimited
	LimitIP           int        // 0 = unlimited concurrent IPs
}

// Client is a newly created client, including its one-time plaintext
// secrets. Plaintext is never persisted or returned again after this —
// only the encrypted columns remain in the database.
type Client struct {
	ID                int64
	Email             string
	XUIInboundID      int
	VlessUUID         string
	Hysteria2Username string
	Hysteria2Password string
	SubID             string
	TrafficLimitBytes int64
	LimitIP           int
	ExpiresAt         *time.Time
	Enabled           bool
	CreatedAt         time.Time
}
