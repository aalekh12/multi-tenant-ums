package tenant

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// PgRepository is the PostgreSQL implementation of Repository.
type PgRepository struct {
	db *pgxpool.Pool
}

// NewRepository creates a new PgRepository.
func NewRepository(db *pgxpool.Pool) *PgRepository {
	return &PgRepository{db: db}
}

// Create inserts a new tenant row.
func (r *PgRepository) Create(ctx context.Context, t *Tenant) error {
	return r.db.QueryRow(ctx, `
		INSERT INTO tenants (name, code, status, is_platform)
		VALUES ($1, $2, $3, $4)
		RETURNING id, created_at, updated_at`,
		t.Name, t.Code, t.Status, t.IsPlatform,
	).Scan(&t.ID, &t.CreatedAt, &t.UpdatedAt)
}

// CreateTx inserts a new tenant row using an existing transaction.
func (r *PgRepository) CreateTx(ctx context.Context, tx pgx.Tx, t *Tenant) error {
	return tx.QueryRow(ctx, `
		INSERT INTO tenants (name, code, status, is_platform)
		VALUES ($1, $2, $3, $4)
		RETURNING id, created_at, updated_at`,
		t.Name, t.Code, t.Status, t.IsPlatform,
	).Scan(&t.ID, &t.CreatedAt, &t.UpdatedAt)
}

// GetByID retrieves a tenant by id.
func (r *PgRepository) GetByID(ctx context.Context, id string) (*Tenant, error) {
	t := &Tenant{}
	err := r.db.QueryRow(ctx,
		`SELECT id, name, code, status, is_platform, created_at, updated_at FROM tenants WHERE id = $1`, id,
	).Scan(&t.ID, &t.Name, &t.Code, &t.Status, &t.IsPlatform, &t.CreatedAt, &t.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	return t, err
}

// GetByCode retrieves a tenant by code (case-insensitive via citext).
func (r *PgRepository) GetByCode(ctx context.Context, code string) (*Tenant, error) {
	t := &Tenant{}
	err := r.db.QueryRow(ctx,
		`SELECT id, name, code, status, is_platform, created_at, updated_at FROM tenants WHERE code = $1`, code,
	).Scan(&t.ID, &t.Name, &t.Code, &t.Status, &t.IsPlatform, &t.CreatedAt, &t.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	return t, err
}

// GetPlatformTenant returns the single platform tenant.
func (r *PgRepository) GetPlatformTenant(ctx context.Context) (*Tenant, error) {
	t := &Tenant{}
	err := r.db.QueryRow(ctx,
		`SELECT id, name, code, status, is_platform, created_at, updated_at FROM tenants WHERE is_platform = true`,
	).Scan(&t.ID, &t.Name, &t.Code, &t.Status, &t.IsPlatform, &t.CreatedAt, &t.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	return t, err
}

// List retrieves tenants with optional filters and pagination.
func (r *PgRepository) List(ctx context.Context, f ListFilter, page, pageSize int) ([]Tenant, int64, error) {
	conds := []string{}
	args := []any{}
	idx := 1

	if f.Status != "" {
		conds = append(conds, fmt.Sprintf("status = $%d", idx))
		args = append(args, f.Status)
		idx++
	}
	if f.Q != "" {
		conds = append(conds, fmt.Sprintf("(name ILIKE $%d OR code ILIKE $%d)", idx, idx))
		args = append(args, "%"+f.Q+"%")
		idx++
	}

	where := ""
	if len(conds) > 0 {
		where = "WHERE " + strings.Join(conds, " AND ")
	}

	offset := (page - 1) * pageSize
	query := fmt.Sprintf(`
		SELECT id, name, code, status, is_platform, created_at, updated_at,
		       COUNT(*) OVER() AS total
		FROM tenants
		%s
		ORDER BY created_at DESC
		LIMIT $%d OFFSET $%d`, where, idx, idx+1)
	args = append(args, pageSize, offset)

	rows, err := r.db.Query(ctx, query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("tenant: list: %w", err)
	}
	defer rows.Close()

	var tenants []Tenant
	var total int64
	for rows.Next() {
		var t Tenant
		if err := rows.Scan(&t.ID, &t.Name, &t.Code, &t.Status, &t.IsPlatform, &t.CreatedAt, &t.UpdatedAt, &total); err != nil {
			return nil, 0, err
		}
		tenants = append(tenants, t)
	}
	return tenants, total, nil
}

// Update updates the name of a tenant.
func (r *PgRepository) Update(ctx context.Context, id, name string) (*Tenant, error) {
	t := &Tenant{}
	err := r.db.QueryRow(ctx, `
		UPDATE tenants SET name = $1, updated_at = now() WHERE id = $2
		RETURNING id, name, code, status, is_platform, created_at, updated_at`, name, id,
	).Scan(&t.ID, &t.Name, &t.Code, &t.Status, &t.IsPlatform, &t.CreatedAt, &t.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	return t, err
}

// UpdateTx updates the name of a tenant within a transaction.
func (r *PgRepository) UpdateTx(ctx context.Context, tx pgx.Tx, id, name string) (*Tenant, error) {
	t := &Tenant{}
	err := tx.QueryRow(ctx, `
		UPDATE tenants SET name = $1, updated_at = now() WHERE id = $2
		RETURNING id, name, code, status, is_platform, created_at, updated_at`, name, id,
	).Scan(&t.ID, &t.Name, &t.Code, &t.Status, &t.IsPlatform, &t.CreatedAt, &t.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	return t, err
}

// SetStatus sets the status of a tenant (active/suspended).
func (r *PgRepository) SetStatus(ctx context.Context, id, status string) (*Tenant, error) {
	t := &Tenant{}
	err := r.db.QueryRow(ctx, `
		UPDATE tenants SET status = $1, updated_at = now() WHERE id = $2
		RETURNING id, name, code, status, is_platform, created_at, updated_at`, status, id,
	).Scan(&t.ID, &t.Name, &t.Code, &t.Status, &t.IsPlatform, &t.CreatedAt, &t.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	return t, err
}

// IsPlatformTenant checks if a given tenant id is the platform tenant.
func (r *PgRepository) IsPlatformTenant(ctx context.Context, id string) (bool, error) {
	var isPlatform bool
	err := r.db.QueryRow(ctx, `SELECT is_platform FROM tenants WHERE id = $1`, id).Scan(&isPlatform)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	return isPlatform, err
}

