package tenant

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/yourusername/usermgmt/internal/audit"
	"github.com/yourusername/usermgmt/internal/platform/cache"
)

var codeRegex = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,62}$`)

// ErrNotFound is returned when a tenant is not found.
var ErrNotFound = errors.New("tenant not found")

// ErrCodeConflict is returned when the code is already in use.
var ErrCodeConflict = errors.New("tenant code already in use")

// ErrCannotSuspendPlatform is returned when suspending the platform tenant.
var ErrCannotSuspendPlatform = errors.New("cannot suspend the platform tenant")

// DefaultRoleCreator creates default roles for a new tenant.
type DefaultRoleCreator interface {
	CreateDefaultRoles(ctx context.Context, tx interface{ Exec(context.Context, string, ...any) (interface{}, error) }, tenantID string, isPlatform bool) error
}

// Service holds tenant business logic.
type Service struct {
	db       *pgxpool.Pool
	repo     *PgRepository
	cache    cache.Cache
	cacheTTL interface{ TenantCacheTTL() interface{} }
	auditor  *audit.Recorder
}

// NewService creates a new tenant Service.
func NewService(db *pgxpool.Pool, repo *PgRepository, c cache.Cache, auditor *audit.Recorder) *Service {
	return &Service{db: db, repo: repo, cache: c, auditor: auditor}
}

// tenantStatusCacheKey returns the cache key for tenant status.
func tenantStatusCacheKey(id string) string {
	return fmt.Sprintf("tenant:status:%s", id)
}

// GetStatus returns the tenant status from cache (or DB on miss).
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
	_ = s.cache.Set(ctx, key, t.Status, 30*1000000000) // 30s
	return t.Status, nil
}

// InvalidateTenantStatus removes the cached status for a tenant.
func (s *Service) InvalidateTenantStatus(ctx context.Context, tenantID string) {
	_ = s.cache.Delete(ctx, tenantStatusCacheKey(tenantID))
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

// UpdateName updates the name of a tenant (for platform-level updates of any tenant).
func (s *Service) UpdateName(ctx context.Context, id, name string) (*Tenant, error) {
	t, err := s.repo.Update(ctx, id, name)
	if err != nil {
		return nil, err
	}
	if t == nil {
		return nil, ErrNotFound
	}
	return t, nil
}

// SetStatus changes tenant status (suspend/activate). Checks platform guard.
func (s *Service) SetStatus(ctx context.Context, tenantID, callerTenantID, status string) (*Tenant, error) {
	if status == "suspended" {
		isPlatform, err := s.repo.IsPlatformTenant(ctx, tenantID)
		if err != nil {
			return nil, err
		}
		if isPlatform {
			return nil, ErrCannotSuspendPlatform
		}
	}

	t, err := s.repo.SetStatus(ctx, tenantID, status)
	if err != nil {
		return nil, err
	}
	if t == nil {
		return nil, ErrNotFound
	}

	// Invalidate cached status
	s.InvalidateTenantStatus(ctx, tenantID)
	return t, nil
}

// validateCode validates a tenant code format.
func validateCode(code string) error {
	if !codeRegex.MatchString(code) {
		return fmt.Errorf("code must match ^[a-z0-9][a-z0-9-]{1,62}$")
	}
	return nil
}

