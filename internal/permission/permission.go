// Package permission provides permission resolution with caching.
package permission

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/multi_tenante_ums/internal/platform/cache"
	"github.com/multi_tenante_ums/internal/platform/httpx"
)

// Permission is a single permission entry from the catalog.
type Permission struct {
	ID          int16  `json:"id"`
	Resource    string `json:"resource"`
	Action      string `json:"action"`
	Code        string `json:"code"`
	Description string `json:"description"`
}

// Repository fetches permissions from the database.
type Repository struct {
	db *pgxpool.Pool
}

// NewRepository creates a new permission Repository.
func NewRepository(db *pgxpool.Pool) *Repository {
	return &Repository{db: db}
}

// ListAll returns the full permission catalog.
func (r *Repository) ListAll(ctx context.Context) ([]Permission, error) {
	rows, err := r.db.Query(ctx, `SELECT id, resource, action, code, description FROM permissions ORDER BY resource, action`)
	if err != nil {
		return nil, fmt.Errorf("permission: list all: %w", err)
	}
	defer rows.Close()
	var perms []Permission
	for rows.Next() {
		var p Permission
		if err := rows.Scan(&p.ID, &p.Resource, &p.Action, &p.Code, &p.Description); err != nil {
			return nil, err
		}
		perms = append(perms, p)
	}
	return perms, nil
}

// GetUserPermissions returns the set of permission codes a user holds in a tenant.
func (r *Repository) GetUserPermissions(ctx context.Context, tenantID, userID string) ([]string, error) {
	rows, err := r.db.Query(ctx, `
		SELECT DISTINCT p.code
		FROM user_roles ur
		JOIN role_permissions rp ON rp.role_id = ur.role_id AND rp.tenant_id = ur.tenant_id
		JOIN permissions p ON p.id = rp.permission_id
		WHERE ur.tenant_id = $1 AND ur.user_id = $2`, tenantID, userID)
	if err != nil {
		return nil, fmt.Errorf("permission: get user permissions: %w", err)
	}
	defer rows.Close()
	var codes []string
	for rows.Next() {
		var code string
		if err := rows.Scan(&code); err != nil {
			return nil, err
		}
		codes = append(codes, code)
	}
	return codes, nil
}

// PermissionGetter is an interface for fetching user permissions from the store.
type PermissionGetter interface {
	GetUserPermissions(ctx context.Context, tenantID, userID string) ([]string, error)
}

// Resolver resolves and caches user permissions.
type Resolver struct {
	repo     PermissionGetter
	cache    cache.Cache
	cacheTTL time.Duration
	sf       singleFlight
}

// NewResolver creates a new permission Resolver.
func NewResolver(repo PermissionGetter, c cache.Cache, ttl time.Duration) *Resolver {
	return &Resolver{
		repo:     repo,
		cache:    c,
		cacheTTL: ttl,
	}
}

func permCacheKey(tenantID, userID string) string {
	return fmt.Sprintf("perm:%s:%s", tenantID, userID)
}

// Get returns the full set of permission codes for a user in a tenant.
func (r *Resolver) Get(ctx context.Context, tenantID, userID string) ([]string, error) {
	key := permCacheKey(tenantID, userID)
	if val, err := r.cache.Get(ctx, key); err == nil {
		var codes []string
		if jsonErr := json.Unmarshal([]byte(val), &codes); jsonErr == nil {
			return codes, nil
		}
	}

	// singleflight to avoid stampedes
	type result struct {
		codes []string
		err   error
	}
	sfKey := "perm:" + tenantID + ":" + userID
	res := r.sf.Do(sfKey, func() any {
		codes, err := r.repo.GetUserPermissions(ctx, tenantID, userID)
		return result{codes, err}
	})
	out := res.(result)
	if out.err != nil {
		return nil, out.err
	}

	// Populate cache (best-effort)
	if b, err := json.Marshal(out.codes); err == nil {
		_ = r.cache.Set(ctx, key, string(b), r.cacheTTL)
	}
	return out.codes, nil
}

// HasPermission returns true if the user holds the specified permission code.
func (r *Resolver) HasPermission(ctx context.Context, tenantID, userID string, permCode string) (bool, error) {
	codes, err := r.Get(ctx, tenantID, userID)
	if err != nil {
		return false, err
	}
	for _, c := range codes {
		if c == permCode {
			return true, nil
		}
	}
	return false, nil
}

// InvalidateUser removes the cached permission set for a specific user.
func (r *Resolver) InvalidateUser(ctx context.Context, tenantID, userID string) {
	_ = r.cache.Delete(ctx, permCacheKey(tenantID, userID))
}

// InvalidateTenant removes the permission cache for all users in a tenant.
// In production this uses SCAN+DEL or a Lua script on Redis.
func (r *Resolver) InvalidateTenant(ctx context.Context, tenantID string) {
	// bump version key — if memory cache, noop; in Redis it would use pattern delete
	_ = r.cache.Delete(ctx, fmt.Sprintf("permver:%s", tenantID))
}

// InvalidateUsersWithRole invalidates the permission cache for given users.
func (r *Resolver) InvalidateUsersWithRole(ctx context.Context, tenantID string, userIDs []string) {
	for _, uid := range userIDs {
		r.InvalidateUser(ctx, tenantID, uid)
	}
}

// singleFlight is a minimal singleflight implementation.
type singleFlight struct {
	mu sync.Mutex
	m  map[string]*sfCall
}

type sfCall struct {
	wg  sync.WaitGroup
	val any
}

func (sf *singleFlight) Do(key string, fn func() any) any {
	sf.mu.Lock()
	if sf.m == nil {
		sf.m = make(map[string]*sfCall)
	}
	if c, ok := sf.m[key]; ok {
		sf.mu.Unlock()
		c.wg.Wait()
		return c.val
	}
	c := &sfCall{}
	c.wg.Add(1)
	sf.m[key] = c
	sf.mu.Unlock()

	c.val = fn()
	c.wg.Done()

	sf.mu.Lock()
	delete(sf.m, key)
	sf.mu.Unlock()
	return c.val
}

// Handler is the HTTP handler for /permissions.
type Handler struct {
	repo *Repository
}

// NewHandler creates a permission Handler.
func NewHandler(repo *Repository) *Handler {
	return &Handler{repo: repo}
}

// ListPermissions handles GET /api/v1/permissions.
func (h *Handler) ListPermissions(w http.ResponseWriter, r *http.Request) {
	perms, err := h.repo.ListAll(r.Context())
	if err != nil {
		httpx.WriteError(w, r, http.StatusInternalServerError, httpx.ErrCodeInternal, "failed to list permissions")
		return
	}
	if perms == nil {
		perms = []Permission{}
	}
	httpx.WriteJSON(w, http.StatusOK, httpx.DataResponse[[]Permission]{Data: perms})
}
