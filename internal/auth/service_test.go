package auth_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/multi_tenante_ums/internal/audit"
	"github.com/multi_tenante_ums/internal/auth"
	"github.com/multi_tenante_ums/internal/platform/cache"
	"github.com/multi_tenante_ums/internal/platform/jwtx"
	"github.com/multi_tenante_ums/internal/platform/password"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

type mockAuthRepo struct {
	user          *auth.UserRow
	membership    *auth.MembershipRow
	tenant        *auth.TenantRow
	roles         []auth.RoleInfo
	refreshTokens map[string]*auth.RefreshToken
	revokedFam    string
	userErr       error
	memErr        error
	tenantErr     error
}

func (m *mockAuthRepo) FindUserByEmail(ctx context.Context, email string) (*auth.UserRow, error) {
	return m.user, m.userErr
}

func (m *mockAuthRepo) GetMembership(ctx context.Context, userID, tenantID string) (*auth.MembershipRow, error) {
	return m.membership, m.memErr
}

func (m *mockAuthRepo) GetUserRoles(ctx context.Context, userID, tenantID string) ([]auth.RoleInfo, error) {
	return m.roles, nil
}

func (m *mockAuthRepo) InsertRefreshToken(ctx context.Context, tx pgx.Tx, rt *auth.RefreshToken) error {
	if m.refreshTokens == nil {
		m.refreshTokens = make(map[string]*auth.RefreshToken)
	}
	m.refreshTokens[rt.JTI] = rt
	return nil
}

func (m *mockAuthRepo) GetRefreshToken(ctx context.Context, jti string) (*auth.RefreshToken, error) {
	if m.refreshTokens == nil {
		return nil, nil
	}
	return m.refreshTokens[jti], nil
}

func (m *mockAuthRepo) MarkRefreshTokenUsed(ctx context.Context, tx pgx.Tx, jti string) error {
	if m.refreshTokens != nil && m.refreshTokens[jti] != nil {
		now := time.Now()
		m.refreshTokens[jti].UsedAt = &now
	}
	return nil
}

func (m *mockAuthRepo) RevokeFamily(ctx context.Context, familyID string) error {
	m.revokedFam = familyID
	return nil
}

func (m *mockAuthRepo) RevokeFamilyTx(ctx context.Context, tx pgx.Tx, familyID string) error {
	m.revokedFam = familyID
	return nil
}

func (m *mockAuthRepo) RevokeUserTenantTokens(ctx context.Context, tx pgx.Tx, userID, tenantID string) error {
	return nil
}

func (m *mockAuthRepo) GetTenantByCode(ctx context.Context, code string) (*auth.TenantRow, error) {
	return m.tenant, m.tenantErr
}

func (m *mockAuthRepo) GetTenantByID(ctx context.Context, id string) (*auth.TenantRow, error) {
	return m.tenant, m.tenantErr
}

func (m *mockAuthRepo) GetUserByID(ctx context.Context, id string) (*auth.UserRow, error) {
	return m.user, m.userErr
}

func (m *mockAuthRepo) GetActiveFamilyBySession(ctx context.Context, familyID, userID, tenantID string) (*auth.RefreshToken, error) {
	for _, rt := range m.refreshTokens {
		if rt.FamilyID == familyID && rt.UserID == userID && rt.TenantID == tenantID {
			return rt, nil
		}
	}
	return nil, nil
}

func setupAuthService(repo *mockAuthRepo) (*auth.Service, *jwtx.Issuer) {
	issuer := jwtx.New(jwtx.Config{
		Secret:   []byte("test-super-secret-key-at-least-32-bytes!"),
		Kid:      "v1",
		Issuer:   "usermgmt",
		Audience: "usermgmt-api",
	})
	hasher := password.New(bcrypt.MinCost)
	c := cache.NewMemory()
	auditor := audit.NewRecorder()

	svc := auth.NewService(&mockDB{}, repo, issuer, hasher, c, auditor, auth.Config{
		AccessTTL:  15 * time.Minute,
		RefreshTTL: 24 * time.Hour,
	})
	return svc, issuer
}

func TestAuthService_Login_Success(t *testing.T) {
	hasher := password.New(bcrypt.MinCost)
	hashed, _ := hasher.Hash("CorrectP@ssword123")

	repo := &mockAuthRepo{
		tenant: &auth.TenantRow{ID: "tenant-1", Code: "acme", Status: "active"},
		user: &auth.UserRow{
			ID: "user-1", Email: "test@acme.test", PasswordHash: hashed, FullName: "Test User",
		},
		membership: &auth.MembershipRow{TenantID: "tenant-1", UserID: "user-1", Status: "active"},
	}

	svc, _ := setupAuthService(repo)

	req := httptest.NewRequest(http.MethodPost, "/auth/login", nil)
	pair, err := svc.Login(context.Background(), req, &auth.LoginInput{
		Email:      "test@acme.test",
		Password:   "CorrectP@ssword123",
		TenantCode: "acme",
	})

	require.NoError(t, err)
	assert.NotEmpty(t, pair.AccessToken)
	assert.NotEmpty(t, pair.RefreshToken)
	assert.Equal(t, 900, pair.ExpiresIn)
}

func TestAuthService_Login_WrongPassword_ReturnsInvalidCredentials(t *testing.T) {
	hasher := password.New(bcrypt.MinCost)
	hashed, _ := hasher.Hash("CorrectP@ssword123")

	repo := &mockAuthRepo{
		tenant: &auth.TenantRow{ID: "tenant-1", Code: "acme", Status: "active"},
		user: &auth.UserRow{
			ID: "user-1", Email: "test@acme.test", PasswordHash: hashed, FullName: "Test User",
		},
		membership: &auth.MembershipRow{TenantID: "tenant-1", UserID: "user-1", Status: "active"},
	}

	svc, _ := setupAuthService(repo)

	req := httptest.NewRequest(http.MethodPost, "/auth/login", nil)
	_, err := svc.Login(context.Background(), req, &auth.LoginInput{
		Email:      "test@acme.test",
		Password:   "WrongP@ssword123",
		TenantCode: "acme",
	})

	assert.ErrorIs(t, err, auth.ErrInvalidCredentials)
}

func TestAuthService_Login_UnknownUser_ReturnsInvalidCredentials(t *testing.T) {
	repo := &mockAuthRepo{
		tenant: &auth.TenantRow{ID: "tenant-1", Code: "acme", Status: "active"},
		user:   nil, // user not found
	}

	svc, _ := setupAuthService(repo)

	req := httptest.NewRequest(http.MethodPost, "/auth/login", nil)
	_, err := svc.Login(context.Background(), req, &auth.LoginInput{
		Email:      "nonexistent@acme.test",
		Password:   "WrongP@ssword123",
		TenantCode: "acme",
	})

	assert.ErrorIs(t, err, auth.ErrInvalidCredentials)
}

func TestAuthService_Login_SuspendedTenant_Returns403(t *testing.T) {
	hasher := password.New(bcrypt.MinCost)
	hashed, _ := hasher.Hash("CorrectP@ssword123")

	repo := &mockAuthRepo{
		tenant: &auth.TenantRow{ID: "tenant-1", Code: "acme", Status: "suspended"},
		user: &auth.UserRow{
			ID: "user-1", Email: "test@acme.test", PasswordHash: hashed, FullName: "Test User",
		},
		membership: &auth.MembershipRow{TenantID: "tenant-1", UserID: "user-1", Status: "active"},
	}

	svc, _ := setupAuthService(repo)

	req := httptest.NewRequest(http.MethodPost, "/auth/login", nil)
	_, err := svc.Login(context.Background(), req, &auth.LoginInput{
		Email:      "test@acme.test",
		Password:   "CorrectP@ssword123",
		TenantCode: "acme",
	})

	assert.ErrorIs(t, err, auth.ErrTenantSuspended)
}

func TestAuthService_Refresh_RotationAndReuseDetection(t *testing.T) {
	repo := &mockAuthRepo{
		tenant:     &auth.TenantRow{ID: "tenant-1", Code: "acme", Status: "active"},
		user:       &auth.UserRow{ID: "user-1", Email: "test@acme.test", FullName: "Test User"},
		membership: &auth.MembershipRow{TenantID: "tenant-1", UserID: "user-1", Status: "active"},
	}

	svc, issuer := setupAuthService(repo)

	// Issue a refresh token
	jti := "rt-jti-1"
	famID := "fam-123"
	tokenStr, err := issuer.IssueRefresh("user-1", "tenant-1", famID, jti, 24*time.Hour)
	require.NoError(t, err)

	repo.refreshTokens = map[string]*auth.RefreshToken{
		jti: {
			JTI:       jti,
			FamilyID:  famID,
			UserID:    "user-1",
			TenantID:  "tenant-1",
			ExpiresAt: time.Now().Add(24 * time.Hour),
		},
	}

	// First refresh: rotates successfully
	req := httptest.NewRequest(http.MethodPost, "/auth/refresh", nil)
	pair, err := svc.Refresh(context.Background(), req, tokenStr)
	require.NoError(t, err)
	assert.NotEmpty(t, pair.AccessToken)
	assert.NotEmpty(t, pair.RefreshToken)

	// Second refresh with SAME used token: reuse detected, revokes family
	_, err = svc.Refresh(context.Background(), req, tokenStr)
	require.Error(t, err)
	assert.ErrorIs(t, err, auth.ErrRefreshReuse)
	assert.Equal(t, famID, repo.revokedFam)
}
