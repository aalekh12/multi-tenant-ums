package role

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// PgRepository is the PostgreSQL implementation of role repository.
type PgRepository struct {
	db *pgxpool.Pool
}

// NewRepository creates a new PgRepository.
func NewRepository(db *pgxpool.Pool) *PgRepository {
	return &PgRepository{db: db}
}

// Create inserts a new role in a tenant.
func (r *PgRepository) Create(ctx context.Context, tenantID, name, description string) (*Role, error) {
	ro := &Role{TenantID: tenantID, Name: name, Description: description, IsSystem: false}
	err := r.db.QueryRow(ctx, `
		INSERT INTO roles (tenant_id, name, description, is_system)
		VALUES ($1, $2, $3, false)
		RETURNING id, created_at, updated_at`,
		tenantID, name, description,
	).Scan(&ro.ID, &ro.CreatedAt, &ro.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return ro, nil
}

// GetByID retrieves a role within a tenant (404 on cross-tenant).
func (r *PgRepository) GetByID(ctx context.Context, tenantID, roleID string) (*Role, error) {
	ro := &Role{TenantID: tenantID}
	err := r.db.QueryRow(ctx, `
		SELECT id, name, description, is_system, created_at, updated_at
		FROM roles
		WHERE id = $1 AND tenant_id = $2`,
		roleID, tenantID,
	).Scan(&ro.ID, &ro.Name, &ro.Description, &ro.IsSystem, &ro.CreatedAt, &ro.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	return ro, err
}

// GetPermissions returns permissions assigned to a role.
func (r *PgRepository) GetPermissions(ctx context.Context, tenantID, roleID string) ([]PermissionRef, error) {
	rows, err := r.db.Query(ctx, `
		SELECT p.id, p.code, p.description
		FROM role_permissions rp
		JOIN permissions p ON p.id = rp.permission_id
		WHERE rp.role_id = $1 AND rp.tenant_id = $2
		ORDER BY p.code`,
		roleID, tenantID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var perms []PermissionRef
	for rows.Next() {
		var pr PermissionRef
		if err := rows.Scan(&pr.ID, &pr.Code, &pr.Description); err != nil {
			return nil, err
		}
		perms = append(perms, pr)
	}
	return perms, nil
}

// List lists roles in a tenant with optional search query and pagination.
func (r *PgRepository) List(ctx context.Context, f ListFilter, page, pageSize int) ([]Role, int64, error) {
	conds := []string{"tenant_id = $1"}
	args := []any{f.TenantID}
	idx := 2

	if f.Q != "" {
		conds = append(conds, fmt.Sprintf("(name ILIKE $%d OR description ILIKE $%d)", idx, idx))
		args = append(args, "%"+f.Q+"%")
		idx++
	}

	where := strings.Join(conds, " AND ")
	offset := (page - 1) * pageSize
	query := fmt.Sprintf(`
		SELECT id, tenant_id, name, description, is_system, created_at, updated_at,
		       COUNT(*) OVER() AS total
		FROM roles
		WHERE %s
		ORDER BY created_at DESC
		LIMIT $%d OFFSET $%d`, where, idx, idx+1)
	args = append(args, pageSize, offset)

	rows, err := r.db.Query(ctx, query, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var roles []Role
	var total int64
	for rows.Next() {
		var ro Role
		if err := rows.Scan(&ro.ID, &ro.TenantID, &ro.Name, &ro.Description, &ro.IsSystem, &ro.CreatedAt, &ro.UpdatedAt, &total); err != nil {
			return nil, 0, err
		}
		roles = append(roles, ro)
	}
	return roles, total, nil
}

// Update updates role name and description within a tenant.
func (r *PgRepository) Update(ctx context.Context, tx pgx.Tx, tenantID, roleID string, name, description *string) (*Role, error) {
	sets := []string{"updated_at = now()"}
	args := []any{roleID, tenantID}
	idx := 3

	if name != nil {
		sets = append(sets, fmt.Sprintf("name = $%d", idx))
		args = append(args, *name)
		idx++
	}
	if description != nil {
		sets = append(sets, fmt.Sprintf("description = $%d", idx))
		args = append(args, *description)
		idx++
	}

	query := fmt.Sprintf(`
		UPDATE roles
		SET %s
		WHERE id = $1 AND tenant_id = $2
		RETURNING id, tenant_id, name, description, is_system, created_at, updated_at`,
		strings.Join(sets, ", "),
	)

	ro := &Role{}
	err := tx.QueryRow(ctx, query, args...).Scan(
		&ro.ID, &ro.TenantID, &ro.Name, &ro.Description, &ro.IsSystem, &ro.CreatedAt, &ro.UpdatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	return ro, err
}

// Delete removes a role from a tenant (cascades permissions and user assignments).
func (r *PgRepository) Delete(ctx context.Context, tx pgx.Tx, tenantID, roleID string) error {
	tag, err := tx.Exec(ctx, `DELETE FROM roles WHERE id = $1 AND tenant_id = $2`, roleID, tenantID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return pgx.ErrNoRows
	}
	return nil
}

// ReplacePermissions replaces a role's permissions within a transaction.
func (r *PgRepository) ReplacePermissions(ctx context.Context, tx pgx.Tx, tenantID, roleID string, permCodes []string) error {
	// Remove current
	_, err := tx.Exec(ctx, `DELETE FROM role_permissions WHERE role_id = $1 AND tenant_id = $2`, roleID, tenantID)
	if err != nil {
		return err
	}

	// Insert new
	for _, code := range permCodes {
		_, err = tx.Exec(ctx, `
			INSERT INTO role_permissions (tenant_id, role_id, permission_id)
			SELECT $1, $2, id FROM permissions WHERE code = $3`,
			tenantID, roleID, code,
		)
		if err != nil {
			return err
		}
	}
	return nil
}

// GetUserIDsWithRole returns the user IDs currently holding this role.
func (r *PgRepository) GetUserIDsWithRole(ctx context.Context, tenantID, roleID string) ([]string, error) {
	rows, err := r.db.Query(ctx, `
		SELECT user_id FROM user_roles WHERE tenant_id = $1 AND role_id = $2`, tenantID, roleID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var uids []string
	for rows.Next() {
		var uid string
		if err := rows.Scan(&uid); err != nil {
			return nil, err
		}
		uids = append(uids, uid)
	}
	return uids, nil
}

