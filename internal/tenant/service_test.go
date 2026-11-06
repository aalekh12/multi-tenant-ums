package tenant_test

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/yourusername/usermgmt/internal/audit"
	"github.com/yourusername/usermgmt/internal/platform/cache"
	"github.com/yourusername/usermgmt/internal/platform/password"
	"github.com/yourusername/usermgmt/internal/tenant"
	"golang.org/x/crypto/bcrypt"
)

type mockDB struct{}

func (m *mockDB) Begin(ctx context.Context) (pgx.Tx, error) {
	return &mockTx{}, nil
}

func (m *mockDB) Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	return pgconn.CommandTag{}, nil
}

func (m *mockDB) Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error) {
	return nil, nil
}

func (m *mockDB) QueryRow(ctx context.Context, sql string, args ...any) pgx.Row {
	return &mockRow{}
}

type mockRow struct{}

func (m *mockRow) Scan(dest ...any) error {
	return pgx.ErrNoRows
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

func (m *mockTx) QueryRow(ctx context.Context, sql string, args ...any) pgx.Row {
	return &mockRow{}
}

type mockTenantRepo struct {
	tenant *tenant.Tenant
	err    error
}

func (m *mockTenantRepo) Create(ctx context.Context, t *tenant.Tenant) error {
	return nil
}

func (m *mockTenantRepo) CreateTx(ctx context.Context, tx pgx.Tx, t *tenant.Tenant) error {
	return nil
}

func (m *mockTenantRepo) GetByID(ctx context.Context, id string) (*tenant.Tenant, error) {
	return m.tenant, m.err
}

func (m *mockTenantRepo) GetByCode(ctx context.Context, code string) (*tenant.Tenant, error) {
	return m.tenant, m.err
}

func (m *mockTenantRepo) GetPlatformTenant(ctx context.Context) (*tenant.Tenant, error) {
	return m.tenant, m.err
}

func (m *mockTenantRepo) List(ctx context.Context, f tenant.ListFilter, page, pageSize int) ([]tenant.Tenant, int64, error) {
	return nil, 0, nil
}

func (m *mockTenantRepo) Update(ctx context.Context, id, name string) (*tenant.Tenant, error) {
	return m.tenant, m.err
}

func (m *mockTenantRepo) SetStatus(ctx context.Context, id, status string) (*tenant.Tenant, error) {
	return m.tenant, m.err
}

func (m *mockTenantRepo) IsPlatformTenant(ctx context.Context, id string) (bool, error) {
	if m.tenant != nil {
		return m.tenant.IsPlatform, nil
	}
	return false, nil
}

func TestTenant_GetStatus_Cached(t *testing.T) {
	ctx := context.Background()
	c := cache.NewMemory()

	// Pre-populate cache
	err := c.Set(ctx, "tenant:status:tenant-1", "active", 30*time.Second)
	require.NoError(t, err)

	svc := tenant.NewService(nil, &mockTenantRepo{}, password.New(bcrypt.MinCost), c, audit.NewRecorder())

	status, err := svc.GetStatus(ctx, "tenant-1")
	require.NoError(t, err)
	assert.Equal(t, "active", status)

	// Invalidate
	svc.InvalidateTenantStatus(ctx, "tenant-1")
	val, err := c.Get(ctx, "tenant:status:tenant-1")
	assert.Empty(t, val)
	assert.True(t, cache.IsNotFound(err))
}

func TestTenant_CodeValidation(t *testing.T) {
	tests := []struct {
		code    string
		wantErr bool
	}{
		{"a", true},         // too short (< 2)
		{"-acme", true},     // starts with hyphen
		{"ACME", false},     // converted to lowercase "acme" which is valid
		{"acme_corp", true}, // underscore not allowed
	}

	for _, tt := range tests {
		t.Run(tt.code, func(t *testing.T) {
			in := &tenant.CreateTenantInput{
				Name: "Acme",
				Code: tt.code,
				Admin: tenant.AdminInput{
					Email:    "admin@acme.test",
					FullName: "Admin",
					Password: "Password123",
				},
			}
			svc := tenant.NewService(&mockDB{}, &mockTenantRepo{}, password.New(bcrypt.MinCost), cache.NewMemory(), audit.NewRecorder())
			_, err := svc.Create(context.Background(), nil, "actor-1", in, false)
			if tt.wantErr {
				assert.Error(t, err)
			}
		})
	}
}
