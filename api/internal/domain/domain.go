// Package domain holds plain data structures for the AC-DB entities that
// don't yet have business logic of their own (P2.2-P2.5 add that). Kept
// separate from any one service package since Region/Node are read by
// multiple future consumers (bootstrap endpoints, EdgeProvisioner).
package domain

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

type User struct {
	ID                uuid.UUID
	Email             string
	PasswordHash      string
	Status            string // trial|active|expired|blocked
	PreferredRegionID *uuid.UUID
	TrialEndsAt       *time.Time
	CreatedAt         time.Time
	UpdatedAt         time.Time
	DeletedAt         *time.Time
}

type UserCredential struct {
	ID          uuid.UUID
	UserID      uuid.UUID
	Protocol    string // vless_reality|hysteria2
	Credential  []byte // encrypted, see internal/crypto
	DeviceLabel *string
	Status      string // active|revoked
	RevokedAt   *time.Time
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

type Region struct {
	ID      uuid.UUID
	Code    string
	Name    string
	Enabled bool
}

type Node struct {
	ID       uuid.UUID
	RegionID uuid.UUID
	IP       string
	Hostname *string
	DecoySNI *string
	Status   string
	Enabled  bool
}

type NodeProtocol struct {
	ID       uuid.UUID
	NodeID   uuid.UUID
	Protocol string
	Port     int
	Priority int16
	Params   json.RawMessage
	Enabled  bool
}
