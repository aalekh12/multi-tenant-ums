package tenant

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/multi_tenante_ums/internal/audit"
	"github.com/multi_tenante_ums/internal/platform/cache"
	"github.com/multi_tenante_ums/internal/platform/password"
)

var codeRegex = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,62}$`)

// Common errors.
var (
	ErrNotFound              = errors.New("tenant not found")
	ErrCodeConflict          = errors.New("tenant code already in use")
	ErrCannotSuspendPlatform = errors.New("cannot suspend the platform tenant")
	ErrNotPlatformTenant     = errors.New("forbidden: platform tenant only")
)

// DB is the database interface for transactions.
type DB interface {
	Begin(ctx context.Context) (pgx.Tx, error)
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// Service holds tenant business logic.
type Service struct {
	db      DB
	repo    Repository
	hasher  *password.Hasher
	cache   cache.Cache
	auditor *audit.Recorder
}

// NewService creates a new tenant Service.
func NewService(db DB, repo Repository, hasher *password.Hasher, c cache.Cache, auditor *audit.Recorder) *Service {
	return &Service{db: db, repo: repo, hasher: hasher, cache: c, auditor: auditor}
}

func tenantStatusCacheKey(id string) string {
	return fmt.Sprintf("tenant:status:%s", id)
}

// GetStatus returns the tenant status from cache (or DB on miss, 30s TTL).
func (s *Service) GetStatus(ctx context.Context, tenantID string) (string, error) {
	key := tenantStatusCacheKey(tenantID)
	if val, err := s.cache.Get(ctx, key); err == nil {
		return val, nil
	}
	t, err := s.repo.GetByID(ctx, tenantID)
	if err != nil {
		return "", err
	}
	if t == nil {
		return "", ErrNotFound
	}
	_ = s.cache.Set(ctx, key, t.Status, 30*time.Second)
	return t.Status, nil
}

// InvalidateTenantStatus removes the cached status for a tenant.
func (s *Service) InvalidateTenantStatus(ctx context.Context, tenantID string) {
	_ = s.cache.Delete(ctx, tenantStatusCacheKey(tenantID))
}

// IsPlatformTenant checks if the given tenant id is the platform tenant.
func (s *Service) IsPlatformTenant(ctx context.Context, tenantID string) (bool, error) {
	return s.repo.IsPlatformTenant(ctx, tenantID)
}

// Create creates a new tenant, default roles, admin user, and membership in one transaction.
func (s *Service) Create(ctx context.Context, r *http.Request, actorID string, in *CreateTenantInput, isPlatform bool) (*Tenant, error) {
	code := strings.ToLower(strings.TrimSpace(in.Code))
	if !codeRegex.MatchString(code) {
		return nil, fmt.Errorf("invalid tenant code format")
	}

	existing, err := s.repo.GetByCode(ctx, code)
	if err != nil {
		return nil, err
	}
	if existing != nil {
		return nil, ErrCodeConflict
	}

	hash, err := s.hasher.Hash(in.Admin.Password)
	if err != nil {
		return nil, fmt.Errorf("hash password: %w", err)
	}

	tx, err := s.db.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// 1. Create tenant row
	t := &Tenant{
		Name:       in.Name,
		Code:       code,
		Status:     "active",
		IsPlatform: isPlatform,
	}
	if err := s.repo.CreateTx(ctx, tx, t); err != nil {
		return nil, fmt.Errorf("create tenant: %w", err)
	}

	// 2. Create default roles and assign permissions
	adminRoleID, err := s.bootstrapDefaultRoles(ctx, tx, t.ID, isPlatform)
	if err != nil {
		return nil, fmt.Errorf("bootstrap roles: %w", err)
	}

	// 3. Create or find admin user
	var adminUserID string
	err = tx.QueryRow(ctx, `
		SELECT id FROM users WHERE email = $1 AND deleted_at IS NULL`, in.Admin.Email,
	).Scan(&adminUserID)

	if errors.Is(err, pgx.ErrNoRows) {
		// Create new global user
		err = tx.QueryRow(ctx, `
			INSERT INTO users (email, password_hash, full_name)
			VALUES ($1, $2, $3)
			RETURNING id`, in.Admin.Email, hash, in.Admin.FullName,
		).Scan(&adminUserID)
		if err != nil {
			return nil, fmt.Errorf("create admin user: %w", err)
		}
	} else if err != nil {
		return nil, fmt.Errorf("find admin user: %w", err)
	}

	// 4. Create membership in tenant_users
	_, err = tx.Exec(ctx, `
		INSERT INTO tenant_users (tenant_id, user_id, status)
		VALUES ($1, $2, 'active')
		ON CONFLICT (tenant_id, user_id) DO UPDATE SET deleted_at = NULL, status = 'active'`,
		t.ID, adminUserID,
	)
	if err != nil {
		return nil, fmt.Errorf("create admin membership: %w", err)
	}

	// 5. Assign admin role (tenant_admin or platform_admin)
	_, err = tx.Exec(ctx, `
		INSERT INTO user_roles (tenant_id, user_id, role_id, assigned_by)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT DO NOTHING`,
		t.ID, adminUserID, adminRoleID, nil,
	)
	if err != nil {
		return nil, fmt.Errorf("assign admin role: %w", err)
	}

	// 6. Record audit
	ip, ua, reqID := audit.EventFromRequest(r)
	actorPtr := (*string)(nil)
	if actorID != "" {
		actorPtr = &actorID
	}
	_ = s.auditor.Record(ctx, tx, audit.Event{
		TenantID:    &t.ID,
		ActorUserID: actorPtr,
		Action:      "tenant.create",
		TargetType:  "tenant",
		TargetID:    &t.ID,
		Metadata: map[string]any{
			"name":        t.Name,
			"code":        t.Code,
			"is_platform": t.IsPlatform,
			"admin_email": in.Admin.Email,
		},
		Success:   true,
		IP:        ip,
		UserAgent: ua,
		RequestID: reqID,
	})

	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	return t, nil
}

// bootstrapDefaultRoles creates the default roles for a tenant inside a transaction.
func (s *Service) bootstrapDefaultRoles(ctx context.Context, tx pgx.Tx, tenantID string, isPlatform bool) (string, error) {
	// Roles definition:
	// tenant_admin (system): all tenant-level permissions
	// user_manager: user:create/read/update/delete
	// viewer: user:read, role:read, permission:read
	// If platform: platform_admin (system) with tenant:create/read/update/suspend + all tenant_admin perms

	type roleDef struct {
		name        string
		description string
		isSystem    bool
		permCodes   []string
	}

	tenantAdminPerms := []string{
		"user:create", "user:read", "user:update", "user:delete",
		"role:create", "role:read", "role:update", "role:delete", "role:assign",
		"permission:read", "permission:assign",
		"audit:read",
		"tenant:read", "tenant:update",
	}

	roles := []roleDef{
		{
			name:        "tenant_admin",
			description: "Full administrator for tenant resources",
			isSystem:    true,
			permCodes:   tenantAdminPerms,
		},
		{
			name:        "user_manager",
			description: "Can manage tenant users",
			isSystem:    false,
			permCodes:   []string{"user:create", "user:read", "user:update", "user:delete"},
		},
		{
			name:        "viewer",
			description: "Read-only access to users, roles, and permissions",
			isSystem:    false,
			permCodes:   []string{"user:read", "role:read", "permission:read"},
		},
	}

	if isPlatform {
		platformPerms := append(append([]string{}, tenantAdminPerms...),
			"tenant:create", "tenant:suspend",
		)
		roles = append(roles, roleDef{
			name:        "platform_admin",
			description: "Superuser with platform and all tenant privileges",
			isSystem:    true,
			permCodes:   platformPerms,
		})
	}

	var primaryAdminRoleID string

	for _, rd := range roles {
		var roleID string
		err := tx.QueryRow(ctx, `
			INSERT INTO roles (tenant_id, name, description, is_system)
			VALUES ($1, $2, $3, $4)
			RETURNING id`, tenantID, rd.name, rd.description, rd.isSystem,
		).Scan(&roleID)
		if err != nil {
			return "", fmt.Errorf("insert role %s: %w", rd.name, err)
		}

		if isPlatform && rd.name == "platform_admin" {
			primaryAdminRoleID = roleID
		} else if !isPlatform && rd.name == "tenant_admin" {
			primaryAdminRoleID = roleID
		}

		// Link permissions
		for _, code := range rd.permCodes {
			_, err = tx.Exec(ctx, `
				INSERT INTO role_permissions (tenant_id, role_id, permission_id)
				SELECT $1, $2, id FROM permissions WHERE code = $3`,
				tenantID, roleID, code,
			)
			if err != nil {
				return "", fmt.Errorf("link perm %s to role %s: %w", code, rd.name, err)
			}
		}
	}

	return primaryAdminRoleID, nil
}

// GetByID retrieves a tenant by id.
func (s *Service) GetByID(ctx context.Context, id string) (*Tenant, error) {
	t, err := s.repo.GetByID(ctx, id)
	if err != nil {
		return nil, err
	}
	if t == nil {
		return nil, ErrNotFound
	}
	return t, nil
}

// GetByCode retrieves a tenant by code.
func (s *Service) GetByCode(ctx context.Context, code string) (*Tenant, error) {
	t, err := s.repo.GetByCode(ctx, strings.ToLower(code))
	if err != nil {
		return nil, err
	}
	if t == nil {
		return nil, ErrNotFound
	}
	return t, nil
}

// List retrieves tenants with filters and pagination.
func (s *Service) List(ctx context.Context, f ListFilter, page, pageSize int) ([]Tenant, int64, error) {
	return s.repo.List(ctx, f, page, pageSize)
}

// UpdateName updates the name of a tenant.
func (s *Service) UpdateName(ctx context.Context, r *http.Request, tenantID, actorID, name string) (*Tenant, error) {
	t, err := s.repo.Update(ctx, tenantID, name)
	if err != nil {
		return nil, err
	}
	if t == nil {
		return nil, ErrNotFound
	}

	ip, ua, reqID := audit.EventFromRequest(r)
	_ = s.auditor.Record(ctx, s.db, audit.Event{
		TenantID:    &tenantID,
		ActorUserID: &actorID,
		Action:      "tenant.update",
		TargetType:  "tenant",
		TargetID:    &tenantID,
		Metadata:    map[string]any{"name": name},
		Success:     true,
		IP:          ip,
		UserAgent:   ua,
		RequestID:   reqID,
	})

	return t, nil
}

// Suspend suspends a tenant, revokes all its active refresh tokens, and invalidates cache.
func (s *Service) Suspend(ctx context.Context, r *http.Request, tenantID, actorID string) (*Tenant, error) {
	isPlatform, err := s.repo.IsPlatformTenant(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	if isPlatform {
		return nil, ErrCannotSuspendPlatform
	}

	tx, err := s.db.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	t := &Tenant{}
	err = tx.QueryRow(ctx, `
		UPDATE tenants SET status = 'suspended', updated_at = now()
		WHERE id = $1
		RETURNING id, name, code, status, is_platform, created_at, updated_at`, tenantID,
	).Scan(&t.ID, &t.Name, &t.Code, &t.Status, &t.IsPlatform, &t.CreatedAt, &t.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}

	// Revoke all active refresh tokens for this tenant
	_, err = tx.Exec(ctx, `
		UPDATE refresh_tokens SET revoked_at = now()
		WHERE tenant_id = $1 AND revoked_at IS NULL`, tenantID,
	)
	if err != nil {
		return nil, fmt.Errorf("revoke tokens on suspend: %w", err)
	}

	ip, ua, reqID := audit.EventFromRequest(r)
	_ = s.auditor.Record(ctx, tx, audit.Event{
		TenantID:    &tenantID,
		ActorUserID: &actorID,
		Action:      "tenant.suspend",
		TargetType:  "tenant",
		TargetID:    &tenantID,
		Success:     true,
		IP:          ip,
		UserAgent:   ua,
		RequestID:   reqID,
	})

	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}

	s.InvalidateTenantStatus(ctx, tenantID)
	return t, nil
}

// Activate restores a suspended tenant.
func (s *Service) Activate(ctx context.Context, r *http.Request, tenantID, actorID string) (*Tenant, error) {
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	t := &Tenant{}
	err = tx.QueryRow(ctx, `
		UPDATE tenants SET status = 'active', updated_at = now()
		WHERE id = $1
		RETURNING id, name, code, status, is_platform, created_at, updated_at`, tenantID,
	).Scan(&t.ID, &t.Name, &t.Code, &t.Status, &t.IsPlatform, &t.CreatedAt, &t.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}

	ip, ua, reqID := audit.EventFromRequest(r)
	_ = s.auditor.Record(ctx, tx, audit.Event{
		TenantID:    &tenantID,
		ActorUserID: &actorID,
		Action:      "tenant.activate",
		TargetType:  "tenant",
		TargetID:    &tenantID,
		Success:     true,
		IP:          ip,
		UserAgent:   ua,
		RequestID:   reqID,
	})

	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}

	s.InvalidateTenantStatus(ctx, tenantID)
	return t, nil
}

// Ptr helper for string pointer.
func Ptr(s string) *string {
	return &s
}

// Ensure dummy usage of uuid
var _ = uuid.New
