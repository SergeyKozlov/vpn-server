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

func (p *ThreeXUIProvisioner) RemoveUser(ctx context.Context, protocol, identifier string) error {
	if protocol != "vless_reality" {
		return fmt.Errorf("threexui: unsupported protocol %q", protocol)
	}
	return p.panel.DeleteClient(ctx, p.inboundID, identifier)
}

func (p *ThreeXUIProvisioner) RotateCredential(ctx context.Context, old, new UserCredentialInput) error {
	return p.panel.UpdateClient(ctx, p.inboundID, old.Identifier, p.toXUIClient(new))
}

func (p *ThreeXUIProvisioner) GetTraffic(ctx context.Context, identifier string) (TrafficStats, error) {
	traffics, err := p.panel.GetClientTrafficsByID(ctx, identifier)
	if err != nil {
		return TrafficStats{}, err
	}
	if len(traffics) == 0 {
		return TrafficStats{}, fmt.Errorf("threexui: no traffic stats for %s", identifier)
	}
	return TrafficStats{Up: traffics[0].Up, Down: traffics[0].Down}, nil
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
