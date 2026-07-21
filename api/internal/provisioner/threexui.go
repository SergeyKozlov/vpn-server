package provisioner

import (
	"context"
	"fmt"

	"vpn-api/internal/xui"
)

// vlessFlow is fixed because the only inbound this adapter targets is a
// VLESS Reality inbound.
const vlessFlow = "xtls-rprx-vision"

// ThreeXUIProvisioner is the VLESS Reality EdgeProvisioner, wrapping the
// existing 3x-ui panel client (internal/xui.Panel) unchanged.
type ThreeXUIProvisioner struct {
	panel     *xui.Panel
	inboundID int
}

func NewThreeXUIProvisioner(panel *xui.Panel, inboundID int) *ThreeXUIProvisioner {
	return &ThreeXUIProvisioner{panel: panel, inboundID: inboundID}
}

func (p *ThreeXUIProvisioner) AddUser(ctx context.Context, cred UserCredentialInput) error {
	return p.panel.AddClient(ctx, p.inboundID, p.toXUIClient(cred))
}

// RemoveUser deletes the client record by email — identifier must be the
// client's email (3x-ui's lookup key since v3.5.0), not the VLESS UUID.
func (p *ThreeXUIProvisioner) RemoveUser(ctx context.Context, protocol, identifier string) error {
	if protocol != "vless_reality" {
		return fmt.Errorf("threexui: unsupported protocol %q", protocol)
	}
	return p.panel.DeleteClient(ctx, identifier)
}

func (p *ThreeXUIProvisioner) RotateCredential(ctx context.Context, old, new UserCredentialInput) error {
	return p.panel.UpdateClient(ctx, old.Email, p.toXUIClient(new))
}

// GetTraffic fetches usage by email — identifier must be the client's
// email, not the VLESS UUID (see RemoveUser).
func (p *ThreeXUIProvisioner) GetTraffic(ctx context.Context, identifier string) (TrafficStats, error) {
	traffic, err := p.panel.GetClientTraffics(ctx, identifier)
	if err != nil {
		return TrafficStats{}, err
	}
	return TrafficStats{Up: traffic.Up, Down: traffic.Down}, nil
}

func (p *ThreeXUIProvisioner) toXUIClient(cred UserCredentialInput) xui.Client {
	return xui.Client{
		ID:         cred.Identifier,
		Email:      cred.Email,
		Flow:       vlessFlow,
		Enable:     true,
		ExpiryTime: cred.ExpiresAt,
		LimitIP:    cred.LimitIP,
		TotalGB:    cred.TotalGB,
		SubID:      cred.SubID,
	}
}
