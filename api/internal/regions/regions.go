// Package regions provides read access to the regions/nodes tables seeded
// by migration 00007. No write path yet — nodes are provisioned manually
// until the second edge node (AC-6.7 reconciler) makes that impractical.
package regions

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"vpn-api/internal/domain"
)

type RegionRepo struct {
	pool *pgxpool.Pool
}

func NewRegionRepo(pool *pgxpool.Pool) *RegionRepo {
	return &RegionRepo{pool: pool}
}

func (r *RegionRepo) List(ctx context.Context) ([]domain.Region, error) {
	rows, err := r.pool.Query(ctx, `SELECT id, code, name, enabled FROM regions ORDER BY code`)
	if err != nil {
		return nil, fmt.Errorf("query regions: %w", err)
	}
	defer rows.Close()

	var out []domain.Region
	for rows.Next() {
		var reg domain.Region
		if err := rows.Scan(&reg.ID, &reg.Code, &reg.Name, &reg.Enabled); err != nil {
			return nil, fmt.Errorf("scan region: %w", err)
		}
		out = append(out, reg)
	}
	return out, rows.Err()
}

type NodeRepo struct {
	pool *pgxpool.Pool
}

func NewNodeRepo(pool *pgxpool.Pool) *NodeRepo {
	return &NodeRepo{pool: pool}
}

func (r *NodeRepo) ListByRegion(ctx context.Context, regionID uuid.UUID) ([]domain.Node, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT id, region_id, ip::text, hostname, decoy_sni, status, enabled
		FROM nodes
		WHERE region_id = $1 AND deleted_at IS NULL
		ORDER BY created_at
	`, regionID)
	if err != nil {
		return nil, fmt.Errorf("query nodes: %w", err)
	}
	defer rows.Close()

	var out []domain.Node
	for rows.Next() {
		var n domain.Node
		if err := rows.Scan(&n.ID, &n.RegionID, &n.IP, &n.Hostname, &n.DecoySNI, &n.Status, &n.Enabled); err != nil {
			return nil, fmt.Errorf("scan node: %w", err)
		}
		out = append(out, n)
	}
	return out, rows.Err()
}
