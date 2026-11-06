package auth

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Repo provides auth-related database operations.
type Repo struct {
	db *pgxpool.Pool
}

// NewRepo creates a new auth Repo.
func NewRepo(db *pgxpool.Pool) *Repo {
	return &Repo{db: db}
}

// FindUserByEmail returns the user with the given email (non-deleted only).
func (r *Repo) FindUserByEmail(ctx context.Context, email string) (*UserRow, error) {
	u := &UserRow{}
	err := r.db.QueryRow(ctx, `
		SELECT id, email, password_hash, full_name, created_at, deleted_at
		FROM users
		WHERE email = $1 AND deleted_at IS NULL`, email,
	).Scan(&u.ID, &u.Email, &u.PasswordHash, &u.FullName, &u.CreatedAt, &u.DeletedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	return u, err
}

// GetMembership returns the tenant_users record for a user/tenant pair.
func (r *Repo) GetMembership(ctx context.Context, userID, tenantID string) (*MembershipRow, error) {
	m := &MembershipRow{}
	err := r.db.QueryRow(ctx, `
		SELECT tenant_id, user_id, status, deleted_at
		FROM tenant_users
		WHERE user_id = $1 AND tenant_id = $2 AND deleted_at IS NULL`, userID, tenantID,
	).Scan(&m.TenantID, &m.UserID, &m.Status, &m.DeletedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	return m, err
}

// GetUserRoles returns the roles a user holds in a tenant.
func (r *Repo) GetUserRoles(ctx context.Context, userID, tenantID string) ([]RoleInfo, error) {
	rows, err := r.db.Query(ctx, `
		SELECT ro.id, ro.name
		FROM user_roles ur
		JOIN roles ro ON ro.id = ur.role_id
		WHERE ur.user_id = $1 AND ur.tenant_id = $2`, userID, tenantID)
	if err != nil {
		return nil, fmt.Errorf("auth: get user roles: %w", err)
	}
	defer rows.Close()
	var roles []RoleInfo
	for rows.Next() {
		var ri RoleInfo
		if err := rows.Scan(&ri.ID, &ri.Name); err != nil {
			return nil, err
		}
		roles = append(roles, ri)
	}
	return roles, nil
}

// InsertRefreshToken inserts a new refresh token row.
func (r *Repo) InsertRefreshToken(ctx context.Context, tx pgx.Tx, rt *RefreshToken) error {
	_, err := tx.Exec(ctx, `
		INSERT INTO refresh_tokens (jti, family_id, user_id, tenant_id, expires_at, ip, user_agent)
		VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		rt.JTI, rt.FamilyID, rt.UserID, rt.TenantID, rt.ExpiresAt, rt.IP, rt.UserAgent,
	)
	return err
}

// GetRefreshToken retrieves a refresh token by JTI.
func (r *Repo) GetRefreshToken(ctx context.Context, jti string) (*RefreshToken, error) {
	rt := &RefreshToken{}
	err := r.db.QueryRow(ctx, `
		SELECT jti, family_id, user_id, tenant_id, expires_at, used_at, revoked_at
		FROM refresh_tokens
		WHERE jti = $1`, jti,
	).Scan(&rt.JTI, &rt.FamilyID, &rt.UserID, &rt.TenantID, &rt.ExpiresAt, &rt.UsedAt, &rt.RevokedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	return rt, err
}

// MarkRefreshTokenUsed sets used_at on a token within a tx.
func (r *Repo) MarkRefreshTokenUsed(ctx context.Context, tx pgx.Tx, jti string) error {
	_, err := tx.Exec(ctx,
		`UPDATE refresh_tokens SET used_at = now() WHERE jti = $1`, jti)
	return err
}

// RevokeFamily revokes all tokens in a family (reuse detection).
func (r *Repo) RevokeFamily(ctx context.Context, familyID string) error {
	_, err := r.db.Exec(ctx,
		`UPDATE refresh_tokens SET revoked_at = now() WHERE family_id = $1 AND revoked_at IS NULL`, familyID)
	return err
}

// RevokeFamilyTx revokes all tokens in a family within a tx.
func (r *Repo) RevokeFamilyTx(ctx context.Context, tx pgx.Tx, familyID string) error {
	_, err := tx.Exec(ctx,
		`UPDATE refresh_tokens SET revoked_at = now() WHERE family_id = $1 AND revoked_at IS NULL`, familyID)
	return err
}

// RevokeUserTenantTokens revokes all active refresh tokens for a user/tenant.
func (r *Repo) RevokeUserTenantTokens(ctx context.Context, tx pgx.Tx, userID, tenantID string) error {
	_, err := tx.Exec(ctx, `
		UPDATE refresh_tokens SET revoked_at = now()
		WHERE user_id = $1 AND tenant_id = $2 AND revoked_at IS NULL`, userID, tenantID)
	return err
}

// GetTenantByCode retrieves a tenant by code.
func (r *Repo) GetTenantByCode(ctx context.Context, code string) (*TenantRow, error) {
	t := &TenantRow{}
	err := r.db.QueryRow(ctx, `
		SELECT id, name, code, status, is_platform
		FROM tenants WHERE code = $1`, code,
	).Scan(&t.ID, &t.Name, &t.Code, &t.Status, &t.IsPlatform)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	return t, err
}

// GetTenantByID retrieves a tenant by id.
func (r *Repo) GetTenantByID(ctx context.Context, id string) (*TenantRow, error) {
	t := &TenantRow{}
	err := r.db.QueryRow(ctx, `
		SELECT id, name, code, status, is_platform
		FROM tenants WHERE id = $1`, id,
	).Scan(&t.ID, &t.Name, &t.Code, &t.Status, &t.IsPlatform)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	return t, err
}

// GetUserByID retrieves a user by id.
func (r *Repo) GetUserByID(ctx context.Context, id string) (*UserRow, error) {
	u := &UserRow{}
	err := r.db.QueryRow(ctx, `
		SELECT id, email, password_hash, full_name, created_at, deleted_at
		FROM users WHERE id = $1 AND deleted_at IS NULL`, id,
	).Scan(&u.ID, &u.Email, &u.PasswordHash, &u.FullName, &u.CreatedAt, &u.DeletedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	return u, err
}

// GetCurrentSessionFamily returns the family_id for the given access token's session.
// We track this by the session ID (sid claim) which equals family_id.
func (r *Repo) GetActiveFamilyBySession(ctx context.Context, familyID, userID, tenantID string) (*RefreshToken, error) {
	rt := &RefreshToken{}
	err := r.db.QueryRow(ctx, `
		SELECT jti, family_id, user_id, tenant_id, expires_at, used_at, revoked_at
		FROM refresh_tokens
		WHERE family_id = $1 AND user_id = $2 AND tenant_id = $3 AND revoked_at IS NULL
		ORDER BY created_at DESC
		LIMIT 1`, familyID, userID, tenantID,
	).Scan(&rt.JTI, &rt.FamilyID, &rt.UserID, &rt.TenantID, &rt.ExpiresAt, &rt.UsedAt, &rt.RevokedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	return rt, err
}

// UserRow is a minimal user record used in auth operations.
type UserRow struct {
	ID           string
	Email        string
	PasswordHash string
	FullName     string
	CreatedAt    time.Time
	DeletedAt    *time.Time
}

// MembershipRow is a minimal tenant_users record.
type MembershipRow struct {
	TenantID  string
	UserID    string
	Status    string
	DeletedAt *time.Time
}

// TenantRow is a minimal tenant record used in auth operations.
type TenantRow struct {
	ID         string
	Name       string
	Code       string
	Status     string
	IsPlatform bool
}
