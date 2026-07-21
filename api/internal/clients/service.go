// Package clients orchestrates creating a VPN client across three systems
// that don't share a transaction: Postgres (the source of truth), the
// 3x-ui panel (VLESS/Reality), and the Hysteria2 config file. Failures
// partway through are unwound with best-effort compensating actions —
// there's no distributed transaction, so a failed rollback is logged
// rather than retried.
package clients

import (
	"context"
	"errors"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"vpn-api/internal/crypto"
	"vpn-api/internal/provisioner"
)

// ErrInvalidParams wraps validation failures on CreateParams so callers
// (the HTTP layer) can map them to 400 instead of 500.
var ErrInvalidParams = errors.New("invalid parameters")

type Service struct {
	pool    *pgxpool.Pool
	vless   provisioner.EdgeProvisioner
	h2      *provisioner.Hysteria2Provisioner
	cryptor *crypto.AESGCM

	inboundID int

	hysteriaMu sync.Mutex // serializes read-modify-write of the userpass map
}

func NewService(pool *pgxpool.Pool, vless provisioner.EdgeProvisioner, h2 *provisioner.Hysteria2Provisioner, cryptor *crypto.AESGCM, inboundID int) *Service {
	return &Service{
		pool:      pool,
		vless:     vless,
		h2:        h2,
		cryptor:   cryptor,
		inboundID: inboundID,
	}
}

func (s *Service) Create(ctx context.Context, params CreateParams) (*Client, error) {
	if params.TrafficLimitBytes < 0 {
		return nil, fmt.Errorf("%w: traffic_limit_bytes must be >= 0", ErrInvalidParams)
	}
	if params.LimitIP < 0 {
		return nil, fmt.Errorf("%w: limit_ip must be >= 0", ErrInvalidParams)
	}

	suffix, err := randomSuffix()
	if err != nil {
		return nil, err
	}
	email := "user_" + suffix
	hysteria2Username := "hy_" + suffix
	subID := "sub_" + suffix

	vlessUUID, err := randomVlessUUID()
	if err != nil {
		return nil, err
	}
	hysteria2Password, err := randomPassword()
	if err != nil {
		return nil, err
	}

	vlessUUIDEnc, err := s.cryptor.Encrypt([]byte(vlessUUID))
	if err != nil {
		return nil, fmt.Errorf("encrypt vless uuid: %w", err)
	}
	hysteria2PasswordEnc, err := s.cryptor.Encrypt([]byte(hysteria2Password))
	if err != nil {
		return nil, fmt.Errorf("encrypt hysteria2 password: %w", err)
	}

	var id int64
	var createdAt time.Time
	err = s.pool.QueryRow(ctx, `
		INSERT INTO legacy_clients_phase1 (email, xui_inbound_id, vless_uuid_enc, hysteria2_username, hysteria2_password_enc, sub_id, traffic_limit_bytes, limit_ip, expires_at, enabled)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, true)
		RETURNING id, created_at
	`, email, s.inboundID, vlessUUIDEnc, hysteria2Username, hysteria2PasswordEnc, subID, params.TrafficLimitBytes, params.LimitIP, params.ExpiresAt).
		Scan(&id, &createdAt)
	if err != nil {
		return nil, fmt.Errorf("insert client: %w", err)
	}

	err = s.vless.AddUser(ctx, provisioner.UserCredentialInput{
		Identifier: vlessUUID,
		Email:      email,
		SubID:      subID,
		ExpiresAt:  expiryMillis(params.ExpiresAt),
		LimitIP:    params.LimitIP,
		TotalGB:    params.TrafficLimitBytes,
	})
	if err != nil {
		s.deleteClientRow(ctx, id)
		return nil, fmt.Errorf("add xui client: %w", err)
	}

	if err := s.syncHysteriaUsers(ctx); err != nil {
		if delErr := s.vless.RemoveUser(ctx, "vless_reality", email); delErr != nil {
			log.Printf("clients: rollback: failed to delete xui client %s after hysteria sync failure: %v", email, delErr)
		}
		s.deleteClientRow(ctx, id)
		return nil, fmt.Errorf("sync hysteria users: %w", err)
	}

	return &Client{
		ID:                id,
		Email:             email,
		XUIInboundID:      s.inboundID,
		VlessUUID:         vlessUUID,
		Hysteria2Username: hysteria2Username,
		Hysteria2Password: hysteria2Password,
		SubID:             subID,
		TrafficLimitBytes: params.TrafficLimitBytes,
		LimitIP:           params.LimitIP,
		ExpiresAt:         params.ExpiresAt,
		Enabled:           true,
		CreatedAt:         createdAt,
	}, nil
}

// syncHysteriaUsers rewrites the Hysteria2 userpass map from every enabled
// client's row (decrypting each stored password), then reloads the
// service. hysteria.SyncUsers replaces the whole map, so every caller must
// go through this — writing only the new user's credentials would wipe out
// everyone else's access.
func (s *Service) syncHysteriaUsers(ctx context.Context) error {
	s.hysteriaMu.Lock()
	defer s.hysteriaMu.Unlock()

	rows, err := s.pool.Query(ctx, `SELECT hysteria2_username, hysteria2_password_enc FROM legacy_clients_phase1 WHERE enabled = true`)
	if err != nil {
		return fmt.Errorf("query hysteria users: %w", err)
	}
	defer rows.Close()

	users := make(map[string]string)
	for rows.Next() {
		var username string
		var passwordEnc []byte
		if err := rows.Scan(&username, &passwordEnc); err != nil {
			return fmt.Errorf("scan hysteria user: %w", err)
		}

		password, err := s.cryptor.Decrypt(passwordEnc)
		if err != nil {
			return fmt.Errorf("decrypt hysteria2 password for %s: %w", username, err)
		}
		users[username] = string(password)
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate hysteria users: %w", err)
	}

	return s.h2.SyncUsers(ctx, users)
}

func (s *Service) deleteClientRow(ctx context.Context, id int64) {
	if _, err := s.pool.Exec(ctx, `DELETE FROM legacy_clients_phase1 WHERE id = $1`, id); err != nil {
		log.Printf("clients: rollback: failed to delete client row %d: %v", id, err)
	}
}

func expiryMillis(t *time.Time) int64 {
	if t == nil {
		return 0
	}
	return t.UnixMilli()
}
