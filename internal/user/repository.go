package user

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// PgRepository is the PostgreSQL repository for user operations.
// All tenant-scoped methods require an explicit tenantID parameter.
type PgRepository struct {
	db *pgxpool.Pool
}

// NewRepository creates a new user PgRepository.
func NewRepository(db *pgxpool.Pool) *PgRepository {
	return &PgRepository{db: db}
}

// DBUser is the internal row type (joins users + tenant_users).
type DBUser struct {
	ID           string
	Email        string
	PasswordHash string
	FullName     string
	Status       string // tenant_users.status
	CreatedAt    time.Time
	UpdatedAt    time.Time
	DeletedAt    *time.Time
	TUDeletedAt  *time.Time
}

// FindByEmail finds a global user by email (non-deleted).
func (r *PgRepository) FindByEmail(ctx context.Context, email string) (*DBUser, error) {
	u := &DBUser{}
	err := r.db.QueryRow(ctx, `
		SELECT id, email, password_hash, full_name, created_at, updated_at, deleted_at
		FROM users WHERE email = $1 AND deleted_at IS NULL`, email,
	).Scan(&u.ID, &u.Email, &u.PasswordHash, &u.FullName, &u.CreatedAt, &u.UpdatedAt, &u.DeletedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	return u, err
}

// FindByEmailTx finds a global user by email within a transaction.
func (r *PgRepository) FindByEmailTx(ctx context.Context, tx pgx.Tx, email string) (*DBUser, error) {
	u := &DBUser{}
	err := tx.QueryRow(ctx, `
		SELECT id, email, password_hash, full_name, created_at, updated_at, deleted_at
		FROM users WHERE email = $1 AND deleted_at IS NULL FOR UPDATE`, email,
	).Scan(&u.ID, &u.Email, &u.PasswordHash, &u.FullName, &u.CreatedAt, &u.UpdatedAt, &u.DeletedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	return u, err
}

// GetByIDInTenant retrieves a user visible within a tenant.
func (r *PgRepository) GetByIDInTenant(ctx context.Context, tenantID, userID string) (*DBUser, error) {
	u := &DBUser{}
	err := r.db.QueryRow(ctx, `
		SELECT u.id, u.email, u.password_hash, u.full_name, tu.status, u.created_at, u.updated_at, u.deleted_at, tu.deleted_at
		FROM users u
		JOIN tenant_users tu ON tu.user_id = u.id AND tu.tenant_id = $1
		WHERE u.id = $2 AND tu.deleted_at IS NULL AND u.deleted_at IS NULL`, tenantID, userID,
	).Scan(&u.ID, &u.Email, &u.PasswordHash, &u.FullName, &u.Status, &u.CreatedAt, &u.UpdatedAt, &u.DeletedAt, &u.TUDeletedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	return u, err
}

// GetMembership retrieves the membership record.
func (r *PgRepository) GetMembership(ctx context.Context, tenantID, userID string) (*MembershipRow, error) {
	m := &MembershipRow{}
	err := r.db.QueryRow(ctx, `
		SELECT tenant_id, user_id, status, deleted_at
		FROM tenant_users WHERE tenant_id = $1 AND user_id = $2`, tenantID, userID,
	).Scan(&m.TenantID, &m.UserID, &m.Status, &m.DeletedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	return m, err
}

// MembershipRow is a tenant_users row.
type MembershipRow struct {
	TenantID  string
	UserID    string
	Status    string
	DeletedAt *time.Time
}

// CountActiveMemberships returns the number of active memberships for a user.
func (r *PgRepository) CountActiveMemberships(ctx context.Context, tx pgx.Tx, userID string) (int, error) {
	var count int
	err := tx.QueryRow(ctx,
		`SELECT COUNT(*) FROM tenant_users WHERE user_id = $1 AND deleted_at IS NULL`, userID,
	).Scan(&count)
	return count, err
}

// CreateUser inserts a new user row in a transaction.
func (r *PgRepository) CreateUser(ctx context.Context, tx pgx.Tx, email, passwordHash, fullName string) (string, time.Time, time.Time, error) {
	var id string
	var createdAt, updatedAt time.Time
	err := tx.QueryRow(ctx, `
		INSERT INTO users (email, password_hash, full_name)
		VALUES ($1, $2, $3)
		RETURNING id, created_at, updated_at`, email, passwordHash, fullName,
	).Scan(&id, &createdAt, &updatedAt)
	return id, createdAt, updatedAt, err
}

// CreateMembership inserts a tenant_users row in a transaction.
func (r *PgRepository) CreateMembership(ctx context.Context, tx pgx.Tx, tenantID, userID, status string) error {
	_, err := tx.Exec(ctx, `
		INSERT INTO tenant_users (tenant_id, user_id, status)
		VALUES ($1, $2, $3)
		ON CONFLICT (tenant_id, user_id) DO UPDATE SET deleted_at = NULL, status = $3, updated_at = now()`,
		tenantID, userID, status)
	return err
}

// AssignRoles assigns a set of roles to a user in a tenant (replaces current set).
func (r *PgRepository) AssignRoles(ctx context.Context, tx pgx.Tx, tenantID, userID, assignedBy string, roleIDs []string) error {
	// Remove existing
	_, err := tx.Exec(ctx,
		`DELETE FROM user_roles WHERE tenant_id = $1 AND user_id = $2`, tenantID, userID)
	if err != nil {
		return fmt.Errorf("user: assign roles delete: %w", err)
	}
	// Insert new
	for _, rid := range roleIDs {
		_, err = tx.Exec(ctx, `
			INSERT INTO user_roles (tenant_id, user_id, role_id, assigned_by)
			VALUES ($1, $2, $3, $4)
			ON CONFLICT DO NOTHING`, tenantID, userID, rid, assignedBy)
		if err != nil {
			return fmt.Errorf("user: assign role %s: %w", rid, err)
		}
	}
	return nil
}

// AddRole adds a single role to a user (idempotent).
func (r *PgRepository) AddRole(ctx context.Context, tx pgx.Tx, tenantID, userID, roleID, assignedBy string) error {
	_, err := tx.Exec(ctx, `
		INSERT INTO user_roles (tenant_id, user_id, role_id, assigned_by)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT DO NOTHING`, tenantID, userID, roleID, assignedBy)
	return err
}

// RemoveRole removes a single role from a user.
func (r *PgRepository) RemoveRole(ctx context.Context, tx pgx.Tx, tenantID, userID, roleID string) error {
	_, err := tx.Exec(ctx,
		`DELETE FROM user_roles WHERE tenant_id = $1 AND user_id = $2 AND role_id = $3`, tenantID, userID, roleID)
	return err
}

// GetUserRoles retrieves roles assigned to a user in a tenant.
func (r *PgRepository) GetUserRoles(ctx context.Context, tenantID, userID string) ([]RoleRef, error) {
	rows, err := r.db.Query(ctx, `
		SELECT ro.id, ro.name
		FROM user_roles ur
		JOIN roles ro ON ro.id = ur.role_id
		WHERE ur.tenant_id = $1 AND ur.user_id = $2`, tenantID, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var roles []RoleRef
	for rows.Next() {
		var rr RoleRef
		if err := rows.Scan(&rr.ID, &rr.Name); err != nil {
			return nil, err
		}
		roles = append(roles, rr)
	}
	return roles, nil
}

// SoftDeleteMembership sets deleted_at on tenant_users and removes user_roles.
func (r *PgRepository) SoftDeleteMembership(ctx context.Context, tx pgx.Tx, tenantID, userID string) error {
	_, err := tx.Exec(ctx, `
		UPDATE tenant_users SET deleted_at = now(), updated_at = now()
		WHERE tenant_id = $1 AND user_id = $2 AND deleted_at IS NULL`, tenantID, userID)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx,
		`DELETE FROM user_roles WHERE tenant_id = $1 AND user_id = $2`, tenantID, userID)
	return err
}

// SoftDeleteUser sets users.deleted_at.
func (r *PgRepository) SoftDeleteUser(ctx context.Context, tx pgx.Tx, userID string) error {
	_, err := tx.Exec(ctx,
		`UPDATE users SET deleted_at = now(), updated_at = now() WHERE id = $1`, userID)
	return err
}

// UpdateUser updates user fields in a tenant context.
func (r *PgRepository) UpdateUser(ctx context.Context, tx pgx.Tx, tenantID, userID string, fullName *string, status *string) error {
	if fullName != nil {
		_, err := tx.Exec(ctx,
			`UPDATE users SET full_name = $1, updated_at = now() WHERE id = $2`, *fullName, userID)
		if err != nil {
			return err
		}
	}
	if status != nil {
		_, err := tx.Exec(ctx, `
			UPDATE tenant_users SET status = $1, updated_at = now()
			WHERE tenant_id = $2 AND user_id = $3`, *status, tenantID, userID)
		if err != nil {
			return err
		}
	}
	return nil
}

// UpdatePassword updates a user's password hash.
func (r *PgRepository) UpdatePassword(ctx context.Context, tx pgx.Tx, userID, hash string) error {
	_, err := tx.Exec(ctx,
		`UPDATE users SET password_hash = $1, updated_at = now() WHERE id = $2`, hash, userID)
	return err
}

// RevokeUserTenantTokens revokes all active refresh tokens for a user in a tenant.
func (r *PgRepository) RevokeUserTenantTokens(ctx context.Context, tx pgx.Tx, userID, tenantID string) error {
	_, err := tx.Exec(ctx, `
		UPDATE refresh_tokens SET revoked_at = now()
		WHERE user_id = $1 AND tenant_id = $2 AND revoked_at IS NULL`, userID, tenantID)
	return err
}

// RoleExists checks if a role belongs to the given tenant.
func (r *PgRepository) RoleExists(ctx context.Context, tenantID, roleID string) (bool, error) {
	var exists bool
	err := r.db.QueryRow(ctx,
		`SELECT EXISTS(SELECT 1 FROM roles WHERE id = $1 AND tenant_id = $2)`, roleID, tenantID,
	).Scan(&exists)
	return exists, err
}

// List retrieves users in a tenant with optional filters and pagination.
func (r *PgRepository) List(ctx context.Context, f ListFilter, page, pageSize int) ([]DBUser, int64, error) {
	conds := []string{"tu.tenant_id = $1"}
	args := []any{f.TenantID}
	idx := 2

	if !f.IncludeDeleted {
		conds = append(conds, "tu.deleted_at IS NULL AND u.deleted_at IS NULL")
	}
	if f.Status != "" {
		conds = append(conds, fmt.Sprintf("tu.status = $%d", idx))
		args = append(args, f.Status)
		idx++
	}
	if f.Q != "" {
		conds = append(conds, fmt.Sprintf("(u.email ILIKE $%d OR u.full_name ILIKE $%d)", idx, idx))
		args = append(args, "%"+f.Q+"%")
		idx++
	}
	if f.RoleID != "" {
		conds = append(conds, fmt.Sprintf(`EXISTS (
			SELECT 1 FROM user_roles ur2 WHERE ur2.tenant_id = tu.tenant_id AND ur2.user_id = u.id AND ur2.role_id = $%d)`, idx))
		args = append(args, f.RoleID)
		idx++
	}

	where := strings.Join(conds, " AND ")
	sortCol := "u.created_at"
	switch f.Sort {
	case "email":
		sortCol = "u.email"
	case "full_name":
		sortCol = "u.full_name"
	}
	order := "DESC"
	if strings.ToUpper(f.Order) == "ASC" {
		order = "ASC"
	}

	offset := (page - 1) * pageSize
	query := fmt.Sprintf(`
		SELECT u.id, u.email, u.password_hash, u.full_name, tu.status, u.created_at, u.updated_at, u.deleted_at, tu.deleted_at,
		       COUNT(*) OVER() AS total
		FROM users u
		JOIN tenant_users tu ON tu.user_id = u.id
		WHERE %s
		ORDER BY %s %s
		LIMIT $%d OFFSET $%d`, where, sortCol, order, idx, idx+1)
	args = append(args, pageSize, offset)

	rows, err := r.db.Query(ctx, query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("user: list: %w", err)
	}
	defer rows.Close()

	var users []DBUser
	var total int64
	for rows.Next() {
		var u DBUser
		if err := rows.Scan(&u.ID, &u.Email, &u.PasswordHash, &u.FullName, &u.Status,
			&u.CreatedAt, &u.UpdatedAt, &u.DeletedAt, &u.TUDeletedAt, &total); err != nil {
			return nil, 0, err
		}
		users = append(users, u)
	}
	return users, total, nil
}
