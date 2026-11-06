package user_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/yourusername/usermgmt/internal/audit"
	"github.com/yourusername/usermgmt/internal/permission"
	"github.com/yourusername/usermgmt/internal/platform/cache"
	"github.com/yourusername/usermgmt/internal/platform/password"
	"github.com/yourusername/usermgmt/internal/user"
	"golang.org/x/crypto/bcrypt"
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

type mockUserRepo struct {
	globalUser        *user.DBUser
	globalUserHash    string
	membership        *user.MembershipRow
	activeMemberships int
	globalUserDeleted bool
	membershipDeleted bool
	tokensRevoked     bool
	createdMembership bool
	createdUser       bool
	rolesAssigned     []string
}

func (m *mockUserRepo) FindByEmail(ctx context.Context, email string) (*user.DBUser, error) {
	return m.globalUser, nil
}

func (m *mockUserRepo) FindByEmailTx(ctx context.Context, tx pgx.Tx, email string) (*user.DBUser, error) {
	return m.globalUser, nil
}

func (m *mockUserRepo) GetByIDInTenant(ctx context.Context, tenantID, userID string) (*user.DBUser, error) {
	if m.globalUser != nil && m.membership != nil && m.membership.TenantID == tenantID && m.membership.DeletedAt == nil {
		return &user.DBUser{
			ID:        m.globalUser.ID,
			Email:     m.globalUser.Email,
			FullName:  m.globalUser.FullName,
			Status:    m.membership.Status,
			CreatedAt: m.globalUser.CreatedAt,
			UpdatedAt: m.globalUser.UpdatedAt,
		}, nil
	}
	return nil, nil
}

func (m *mockUserRepo) GetMembership(ctx context.Context, tenantID, userID string) (*user.MembershipRow, error) {
	return m.membership, nil
}

func (m *mockUserRepo) CountActiveMemberships(ctx context.Context, tx pgx.Tx, userID string) (int, error) {
	return m.activeMemberships, nil
}

func (m *mockUserRepo) CreateUser(ctx context.Context, tx pgx.Tx, email, passwordHash, fullName string) (string, time.Time, time.Time, error) {
	m.createdUser = true
	m.globalUser = &user.DBUser{
		ID:        "new-user-id",
		Email:     email,
		FullName:  fullName,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	m.globalUserHash = passwordHash
	return "new-user-id", time.Now(), time.Now(), nil
}

func (m *mockUserRepo) CreateMembership(ctx context.Context, tx pgx.Tx, tenantID, userID, status string) error {
	m.createdMembership = true
	m.membership = &user.MembershipRow{
		TenantID: tenantID,
		UserID:   userID,
		Status:   status,
	}
	return nil
}

func (m *mockUserRepo) AssignRoles(ctx context.Context, tx pgx.Tx, tenantID, userID, assignedBy string, roleIDs []string) error {
	m.rolesAssigned = roleIDs
	return nil
}

func (m *mockUserRepo) AddRole(ctx context.Context, tx pgx.Tx, tenantID, userID, roleID, assignedBy string) error {
	m.rolesAssigned = append(m.rolesAssigned, roleID)
	return nil
}

func (m *mockUserRepo) RemoveRole(ctx context.Context, tx pgx.Tx, tenantID, userID, roleID string) error {
	return nil
}

func (m *mockUserRepo) GetUserRoles(ctx context.Context, tenantID, userID string) ([]user.RoleRef, error) {
	return []user.RoleRef{}, nil
}

func (m *mockUserRepo) SoftDeleteMembership(ctx context.Context, tx pgx.Tx, tenantID, userID string) error {
	m.membershipDeleted = true
	if m.membership != nil {
		now := time.Now()
		m.membership.DeletedAt = &now
	}
	return nil
}

func (m *mockUserRepo) SoftDeleteUser(ctx context.Context, tx pgx.Tx, userID string) error {
	m.globalUserDeleted = true
	return nil
}

func (m *mockUserRepo) UpdateUser(ctx context.Context, tx pgx.Tx, tenantID, userID string, fullName *string, status *string) error {
	return nil
}

func (m *mockUserRepo) UpdatePassword(ctx context.Context, tx pgx.Tx, userID, hash string) error {
	m.globalUserHash = hash
	return nil
}

func (m *mockUserRepo) RevokeUserTenantTokens(ctx context.Context, tx pgx.Tx, userID, tenantID string) error {
	m.tokensRevoked = true
	return nil
}

func (m *mockUserRepo) RoleExists(ctx context.Context, tenantID, roleID string) (bool, error) {
	return true, nil
}

func (m *mockUserRepo) List(ctx context.Context, f user.ListFilter, page, pageSize int) ([]user.DBUser, int64, error) {
	return nil, 0, nil
}

type mockPermResolver struct{}

func (m *mockPermResolver) GetUserPermissions(ctx context.Context, tenantID, userID string) ([]string, error) {
	return []string{}, nil
}

func setupUserService(repo user.Repository) *user.Service {
	hasher := password.New(bcrypt.MinCost)
	c := cache.NewMemory()
	auditor := audit.NewRecorder()
	permRes := permission.NewResolver(&mockPermResolver{}, c, time.Minute)

	return user.NewService(&mockDB{}, repo, hasher, permRes, c, auditor)
}

func TestUserService_Decision3_ExistingGlobalEmail_AttachesMembership(t *testing.T) {
	// User exists globally with original name and password hash
	existingUser := &user.DBUser{
		ID:        "global-user-1",
		Email:     "shared@example.test",
		FullName:  "Original Name",
		CreatedAt: time.Now().Add(-24 * time.Hour),
		UpdatedAt: time.Now().Add(-24 * time.Hour),
	}

	repo := &mockUserRepo{
		globalUser:     existingUser,
		globalUserHash: "original_hashed_password",
		membership:     nil, // Not yet a member of tenant-A
	}

	svc := setupUserService(repo)
	req := httptest.NewRequest(http.MethodPost, "/users", nil)

	in := &user.CreateUserInput{
		Email:    "shared@example.test",
		FullName: "Different Name In Input",
		Password: "NewPassword123",
	}

	created, err := svc.Create(context.Background(), req, "tenant-A", "admin-1", in)
	require.NoError(t, err)

	// Decision 3 assertions:
	// 1. Returns 201 user shape with global user ID
	assert.Equal(t, "global-user-1", created.ID)
	// 2. Name and password of global user are NOT modified
	assert.Equal(t, "Original Name", created.FullName)
	assert.Equal(t, "original_hashed_password", repo.globalUserHash)
	assert.False(t, repo.createdUser, "must not insert new row into users table")
	// 3. Membership in tenant-A is created
	assert.True(t, repo.createdMembership)
	assert.Equal(t, "tenant-A", repo.membership.TenantID)
}

func TestUserService_Decision3_AlreadyActiveMember_ReturnsConflict(t *testing.T) {
	existingUser := &user.DBUser{
		ID:       "global-user-1",
		Email:    "shared@example.test",
		FullName: "Existing Member",
	}

	repo := &mockUserRepo{
		globalUser: existingUser,
		membership: &user.MembershipRow{
			TenantID:  "tenant-A",
			UserID:    "global-user-1",
			Status:    "active",
			DeletedAt: nil, // already active in this tenant
		},
	}

	svc := setupUserService(repo)
	req := httptest.NewRequest(http.MethodPost, "/users", nil)

	in := &user.CreateUserInput{
		Email:    "shared@example.test",
		FullName: "Existing Member",
		Password: "Password123",
	}

	_, err := svc.Create(context.Background(), req, "tenant-A", "admin-1", in)
	assert.ErrorIs(t, err, user.ErrEmailConflict)
}

func TestUserService_Decision2_CannotDeleteSelf(t *testing.T) {
	repo := &mockUserRepo{}
	svc := setupUserService(repo)

	req := httptest.NewRequest(http.MethodDelete, "/users/user-1", nil)
	// actorID == userID
	err := svc.Delete(context.Background(), req, "tenant-A", "user-1", "user-1")
	assert.ErrorIs(t, err, user.ErrSelfDelete)
}

func TestUserService_Decision2_SoftDelete_WithRemainingMemberships(t *testing.T) {
	targetUser := &user.DBUser{
		ID:       "user-target",
		Email:    "multi@example.test",
		FullName: "Multi Tenant User",
	}

	repo := &mockUserRepo{
		globalUser: targetUser,
		membership: &user.MembershipRow{
			TenantID: "tenant-A",
			UserID:   "user-target",
			Status:   "active",
		},
		activeMemberships: 1, // Still has 1 active membership in tenant-B
	}

	svc := setupUserService(repo)
	req := httptest.NewRequest(http.MethodDelete, "/users/user-target", nil)

	err := svc.Delete(context.Background(), req, "tenant-A", "user-target", "admin-1")
	require.NoError(t, err)

	// Per-tenant membership deleted and tokens revoked
	assert.True(t, repo.membershipDeleted)
	assert.True(t, repo.tokensRevoked)
	// Global user must NOT be deleted because user is still active in tenant-B
	assert.False(t, repo.globalUserDeleted)
}

func TestUserService_Decision2_SoftDelete_ZeroRemainingMemberships(t *testing.T) {
	targetUser := &user.DBUser{
		ID:       "user-target",
		Email:    "single@example.test",
		FullName: "Single Tenant User",
	}

	repo := &mockUserRepo{
		globalUser: targetUser,
		membership: &user.MembershipRow{
			TenantID: "tenant-A",
			UserID:   "user-target",
			Status:   "active",
		},
		activeMemberships: 0, // No remaining memberships left anywhere
	}

	svc := setupUserService(repo)
	req := httptest.NewRequest(http.MethodDelete, "/users/user-target", nil)

	err := svc.Delete(context.Background(), req, "tenant-A", "user-target", "admin-1")
	require.NoError(t, err)

	// Both per-tenant membership AND global user row are soft-deleted
	assert.True(t, repo.membershipDeleted)
	assert.True(t, repo.tokensRevoked)
	assert.True(t, repo.globalUserDeleted)
}
