// Package provisioner defines the EdgeProvisioner abstraction (AC-6.8) over
// per-protocol edge state: 3x-ui for VLESS Reality, the Hysteria2
// config.yaml userpass map for Hysteria2. Business logic (internal/clients)
// talks to this interface instead of holding *xui.Panel/hysteria.SyncUsers
// directly, so swapping the panel or moving to direct Xray management later
// is an adapter change, not a rewrite of clients.Service.
package provisioner

import "context"

// UserCredentialInput carries what an implementation needs to add or rotate
// one user's credential on the edge. Not every field applies to every
// protocol (e.g. Flow/LimitIP/TotalGB are VLESS-only) — implementations
// ignore what they don't use.
type UserCredentialInput struct {
	Identifier string // VLESS UUID, or Hysteria2 username
	Secret     string // VLESS UUID again (identifier==secret there), or Hysteria2 password
	Email      string // 3x-ui client label; unused by Hysteria2
	SubID      string // 3x-ui subscription id; unused by Hysteria2
	ExpiresAt  int64  // epoch millis, 0 = never (3x-ui only)
	LimitIP    int
	TotalGB    int64
}

type TrafficStats struct {
	Up   int64
	Down int64
}

// EdgeProvisioner manages one user's presence on one protocol's edge state.
type EdgeProvisioner interface {
	AddUser(ctx context.Context, cred UserCredentialInput) error
	RemoveUser(ctx context.Context, protocol, identifier string) error
	RotateCredential(ctx context.Context, old, new UserCredentialInput) error
	GetTraffic(ctx context.Context, identifier string) (TrafficStats, error)
}
