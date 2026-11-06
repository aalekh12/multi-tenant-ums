package role_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/multi_tenante_ums/internal/audit"
	"github.com/multi_tenante_ums/internal/permission"
	"github.com/multi_tenante_ums/internal/platform/cache"
	"github.com/multi_tenante_ums/internal/role"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockDB struct{}

func (m *mockDB) Begin(ctx context.Context) (pgx.Tx, error) {
	return &mockTx{}, nil
}

func (m *mockDB) Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	return pgconn.CommandTag{}, nil
}

type mockTx struct {
	pgx.Tx
}

func (m *mockTx) Commit(ctx context.Context) error {
	return nil
}

func (m *mockTx) Rollback(ctx context.Context) error {
	return nil
}

func (m *mockTx) Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	return pgconn.CommandTag{}, nil
}

type mockRoleRepo struct {
	roles         map[string]*role.Role
	perms         map[string][]role.PermissionRef
	usersWithRole []string
	replacedPerms []string
	roleDeleted   bool
	roleUpdated   bool
}

func newMockRoleRepo() *mockRoleRepo {
	return &mockRoleRepo{
		roles: make(map[string]*role.Role),
		perms: make(map[string][]role.PermissionRef),
	}
}

func (m *mockRoleRepo) Create(ctx context.Context, tenantID, name, description string) (*role.Role, error) {
	ro := &role.Role{
		ID:          "role-123",
		TenantID:    tenantID,
		Name:        name,
		Description: description,
		IsSystem:    false,
	}
	m.roles[ro.ID] = ro
	return ro, nil
}

func (m *mockRoleRepo) GetByID(ctx context.Context, tenantID, roleID string) (*role.Role, error) {
	ro := m.roles[roleID]
	if ro != nil && ro.TenantID == tenantID {
		return ro, nil
	}
	return nil, nil
}

func (m *mockRoleRepo) GetPermissions(ctx context.Context, tenantID, roleID string) ([]role.PermissionRef, error) {
	return m.perms[roleID], nil
}

func (m *mockRoleRepo) List(ctx context.Context, f role.ListFilter, page, pageSize int) ([]role.Role, int64, error) {
	return nil, 0, nil
}

func (m *mockRoleRepo) Update(ctx context.Context, tx pgx.Tx, tenantID, roleID string, name, description *string) (*role.Role, error) {
	m.roleUpdated = true
	ro := m.roles[roleID]
	if name != nil {
		ro.Name = *name
	}
	if description != nil {
		ro.Description = *description
	}
	return ro, nil
}

func (m *mockRoleRepo) Delete(ctx context.Context, tx pgx.Tx, tenantID, roleID string) error {
	m.roleDeleted = true
	delete(m.roles, roleID)
	return nil
}

func (m *mockRoleRepo) ReplacePermissions(ctx context.Context, tx pgx.Tx, tenantID, roleID string, permCodes []string) error {
	m.replacedPerms = permCodes
	return nil
}

func (m *mockRoleRepo) GetUserIDsWithRole(ctx context.Context, tenantID, roleID string) ([]string, error) {
	return m.usersWithRole, nil
}

type mockPermGetter struct {
	actorPerms []string
}

func (m *mockPermGetter) GetUserPermissions(ctx context.Context, tenantID, userID string) ([]string, error) {
	return m.actorPerms, nil
}

func setupRoleService(repo *mockRoleRepo, actorPerms []string, c cache.Cache) *role.Service {
	permRes := permission.NewResolver(&mockPermGetter{actorPerms: actorPerms}, c, 5*time.Minute)
	return role.NewService(&mockDB{}, repo, permRes, audit.NewRecorder())
}

func TestRoleService_SystemRole_Immutable(t *testing.T) {
	repo := newMockRoleRepo()
	repo.roles["system-role-1"] = &role.Role{
		ID:       "system-role-1",
		TenantID: "tenant-A",
		Name:     "tenant_admin",
		IsSystem: true,
	}

	c := cache.NewMemory()
	svc := setupRoleService(repo, []string{"role:update", "role:delete", "permission:assign"}, c)
	req := httptest.NewRequest(http.MethodPatch, "/roles/system-role-1", nil)

	// 1. Rename system role -> forbidden
	newName := "renamed_admin"
	_, err := svc.Update(context.Background(), req, "tenant-A", "system-role-1", "actor-1", &role.UpdateRoleInput{Name: &newName})
	assert.ErrorIs(t, err, role.ErrSystemRoleImmutable)

	// 2. Delete system role -> forbidden
	err = svc.Delete(context.Background(), req, "tenant-A", "system-role-1", "actor-1")
	assert.ErrorIs(t, err, role.ErrSystemRoleImmutable)

	// 3. Change system role permissions -> forbidden
	err = svc.AssignPermissions(context.Background(), req, "tenant-A", "system-role-1", "actor-1", &role.AssignPermissionsInput{
		PermissionCodes: []string{"user:read"},
	})
	assert.ErrorIs(t, err, role.ErrSystemRoleImmutable)
}

func TestRoleService_PrivilegeEscalation_Guard(t *testing.T) {
	repo := newMockRoleRepo()
	repo.roles["custom-role-1"] = &role.Role{
		ID:       "custom-role-1",
		TenantID: "tenant-A",
		Name:     "custom_role",
		IsSystem: false,
	}

	c := cache.NewMemory()
	// Actor only holds "user:read" and "role:read"
	svc := setupRoleService(repo, []string{"user:read", "role:read"}, c)
	req := httptest.NewRequest(http.MethodPut, "/roles/custom-role-1/permissions", nil)

	// Attempting to grant "user:delete" (which actor does NOT hold) -> blocked!
	err := svc.AssignPermissions(context.Background(), req, "tenant-A", "custom-role-1", "actor-1", &role.AssignPermissionsInput{
		PermissionCodes: []string{"user:read", "user:delete"},
	})
	assert.ErrorIs(t, err, role.ErrPrivilegeEscalation)
	assert.Empty(t, repo.replacedPerms)

	// Granting permissions actor DOES hold -> success!
	err = svc.AssignPermissions(context.Background(), req, "tenant-A", "custom-role-1", "actor-1", &role.AssignPermissionsInput{
		PermissionCodes: []string{"user:read"},
	})
	require.NoError(t, err)
	assert.Equal(t, []string{"user:read"}, repo.replacedPerms)
}

func TestRoleService_CacheInvalidation_OnPermissionChange(t *testing.T) {
	repo := newMockRoleRepo()
	repo.roles["custom-role-1"] = &role.Role{
		ID:       "custom-role-1",
		TenantID: "tenant-A",
		Name:     "custom_role",
		IsSystem: false,
	}
	repo.usersWithRole = []string{"user-A", "user-B"}

	c := cache.NewMemory()
	// Pre-populate user cache
	_ = c.Set(context.Background(), "perm:tenant-A:user-A", "[\"old:perm\"]", 5*time.Minute)
	_ = c.Set(context.Background(), "perm:tenant-A:user-B", "[\"old:perm\"]", 5*time.Minute)

	svc := setupRoleService(repo, []string{"user:read"}, c)
	req := httptest.NewRequest(http.MethodPut, "/roles/custom-role-1/permissions", nil)

	err := svc.AssignPermissions(context.Background(), req, "tenant-A", "custom-role-1", "actor-1", &role.AssignPermissionsInput{
		PermissionCodes: []string{"user:read"},
	})
	require.NoError(t, err)

	// Caches for users holding this role must be deleted
	_, errA := c.Get(context.Background(), "perm:tenant-A:user-A")
	assert.True(t, cache.IsNotFound(errA))

	_, errB := c.Get(context.Background(), "perm:tenant-A:user-B")
	assert.True(t, cache.IsNotFound(errB))
}

func TestRoleService_CrossTenant_RoleNotFound(t *testing.T) {
	repo := newMockRoleRepo()
	// Role belongs to tenant-B
	repo.roles["role-in-B"] = &role.Role{
		ID:       "role-in-B",
		TenantID: "tenant-B",
		Name:     "role_in_B",
	}

	c := cache.NewMemory()
	svc := setupRoleService(repo, []string{"role:read"}, c)

	// Query using tenant-A -> must return ErrRoleNotFound (never reveals tenant-B's role)
	_, err := svc.GetByID(context.Background(), "tenant-A", "role-in-B")
	assert.ErrorIs(t, err, role.ErrRoleNotFound)
}
