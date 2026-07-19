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
	"vpn-api/internal/hysteria"
	"vpn-api/internal/xui"
)

// ErrInvalidParams wraps validation failures on CreateParams so callers
// (the HTTP layer) can map them to 400 instead of 500.
var ErrInvalidParams = errors.New("invalid parameters")

// vlessFlow is fixed because the only inbound this service targets
// (xui_inbound_id) is a VLESS Reality inbound.
const vlessFlow = "xtls-rprx-vision"

type Service struct {
	pool    *pgxpool.Pool
	panel   *xui.Panel
	cryptor *crypto.AESGCM

	inboundID int

	hysteriaConfigPath    string
	hysteriaReloadCommand string
	hysteriaMu            sync.Mutex // serializes read-modify-write of the userpass map
}

func NewService(pool *pgxpool.Pool, panel *xui.Panel, cryptor *crypto.AESGCM, inboundID int, hysteriaConfigPath, hysteriaReloadCommand string) *Service {
	return &Service{
		pool:                  pool,
		panel:                 panel,
		cryptor:               cryptor,
		inboundID:             inboundID,
		hysteriaConfigPath:    hysteriaConfigPath,
		hysteriaReloadCommand: hysteriaReloadCommand,
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
		INSERT INTO clients (email, xui_inbound_id, vless_uuid_enc, hysteria2_username, hysteria2_password_enc, sub_id, traffic_limit_bytes, limit_ip, expires_at, enabled)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, true)
		RETURNING id, created_at
	`, email, s.inboundID, vlessUUIDEnc, hysteria2Username, hysteria2PasswordEnc, subID, params.TrafficLimitBytes, params.LimitIP, params.ExpiresAt).
		Scan(&id, &createdAt)
	if err != nil {
		return nil, fmt.Errorf("insert client: %w", err)
	}

	err = s.panel.AddClient(ctx, s.inboundID, xui.Client{
		ID:         vlessUUID,
		Email:      email,
		Flow:       vlessFlow,
		Enable:     true,
		ExpiryTime: expiryMillis(params.ExpiresAt),
		LimitIP:    params.LimitIP,
		TotalGB:    params.TrafficLimitBytes,
		SubID:      subID,
	})
	if err != nil {
		s.deleteClientRow(ctx, id)
		return nil, fmt.Errorf("add xui client: %w", err)
	}

	if err := s.syncHysteriaUsers(ctx); err != nil {
		if delErr := s.panel.DeleteClient(ctx, s.inboundID, vlessUUID); delErr != nil {
			log.Printf("clients: rollback: failed to delete xui client %s after hysteria sync failure: %v", vlessUUID, delErr)
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

	rows, err := s.pool.Query(ctx, `SELECT hysteria2_username, hysteria2_password_enc FROM clients WHERE enabled = true`)
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

	return hysteria.SyncUsers(ctx, s.hysteriaConfigPath, users, s.hysteriaReloadCommand)
}

func (s *Service) deleteClientRow(ctx context.Context, id int64) {
	if _, err := s.pool.Exec(ctx, `DELETE FROM clients WHERE id = $1`, id); err != nil {
		log.Printf("clients: rollback: failed to delete client row %d: %v", id, err)
	}
}

func expiryMillis(t *time.Time) int64 {
	if t == nil {
		return 0
	}
	return t.UnixMilli()
}
