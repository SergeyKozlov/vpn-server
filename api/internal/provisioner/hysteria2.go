package provisioner

import (
	"context"
	"errors"
	"fmt"

	"vpn-api/internal/hysteria"
)

// Hysteria2Provisioner is the Hysteria2 EdgeProvisioner: native auth via a
// static userpass map in config.yaml (AC-3.2), wrapping the existing
// internal/hysteria package unchanged.
type Hysteria2Provisioner struct {
	configPath    string
	reloadCommand string
}

func NewHysteria2Provisioner(configPath, reloadCommand string) *Hysteria2Provisioner {
	return &Hysteria2Provisioner{configPath: configPath, reloadCommand: reloadCommand}
}

func (h *Hysteria2Provisioner) AddUser(ctx context.Context, cred UserCredentialInput) error {
	return h.mutate(ctx, func(users map[string]string) {
		users[cred.Identifier] = cred.Secret
	})
}

func (h *Hysteria2Provisioner) RemoveUser(ctx context.Context, protocol, identifier string) error {
	if protocol != "hysteria2" {
		return fmt.Errorf("hysteria2: unsupported protocol %q", protocol)
	}
	return h.mutate(ctx, func(users map[string]string) {
		delete(users, identifier)
	})
}

func (h *Hysteria2Provisioner) RotateCredential(ctx context.Context, old, new UserCredentialInput) error {
	return h.mutate(ctx, func(users map[string]string) {
		delete(users, old.Identifier)
		users[new.Identifier] = new.Secret
	})
}

// GetTraffic is unsupported: native userpass auth has no per-user stats API
// (that's why 3x-ui is authoritative for traffic accounting, see AC-6.5).
func (h *Hysteria2Provisioner) GetTraffic(ctx context.Context, identifier string) (TrafficStats, error) {
	return TrafficStats{}, errors.New("hysteria2: traffic stats not available via native auth")
}

// SyncUsers replaces the entire userpass map wholesale. clients.Service is
// the source of truth for "who should have access" — it queries every
// enabled client row and calls this instead of the incremental
// AddUser/RemoveUser above, matching the pre-refactor
// hysteria.SyncUsers call it replaces.
func (h *Hysteria2Provisioner) SyncUsers(ctx context.Context, users map[string]string) error {
	return hysteria.SyncUsers(ctx, h.configPath, users, h.reloadCommand)
}

func (h *Hysteria2Provisioner) mutate(ctx context.Context, fn func(map[string]string)) error {
	cfg, err := hysteria.LoadConfig(h.configPath)
	if err != nil {
		return err
	}

	users := make(map[string]string, len(cfg.Auth.UserPass))
	for k, v := range cfg.Auth.UserPass {
		users[k] = v
	}
	fn(users)

	return hysteria.SyncUsers(ctx, h.configPath, users, h.reloadCommand)
}
