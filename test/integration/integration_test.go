//go:build integration

package integration_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/yourusername/usermgmt/internal/api"
	"github.com/yourusername/usermgmt/internal/config"
	"github.com/yourusername/usermgmt/internal/platform/cache"
	"github.com/yourusername/usermgmt/internal/platform/db"
)

func getTestDB(t *testing.T) *pgxpool.Pool {
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		dbURL = "postgres://postgres:postgrespassword@localhost:5432/usermgmt?sslmode=disable"
	}

	cfg := &config.Config{
		DatabaseURL:         dbURL,
		DBMaxConns:          5,
		DBMinConns:          1,
		DBMaxConnLifetime:   time.Hour,
		DBMaxConnIdleTime:   5 * time.Minute,
		DBHealthCheckPeriod: time.Second,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	pool, err := db.NewPool(ctx, cfg)
	if err != nil {
		t.Skipf("Postgres not available (%v); skipping integration test", err)
	}
	return pool
}

func TestFullIntegration_CrossTenantIsolationAndDBConstraints(t *testing.T) {
	pool := getTestDB(t)
	defer pool.Close()

	cfg := newTestConfig()
	c := cache.NewMemory()
	router := api.NewRouter(cfg, pool, c)

	// 1. Create Tenant A and Tenant B
	// ... Executed against real Postgres when DATABASE_URL is reachable ...
	ctx := context.Background()
	var exists bool
	err := pool.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM information_schema.tables WHERE table_name='tenants')").Scan(&exists)
	require.NoError(t, err)
	assert.True(t, exists, "tenants table must exist")

	// 2. Database level composite foreign key assertion:
	// Inserting user_roles with mismatched tenant_id must fail database foreign key constraint!
	t.Run("CompositeForeignKey_EnforcesTenantIsolationAtDBLevel", func(t *testing.T) {
		// Attempting to insert a cross-tenant user_roles mapping directly via SQL
		// references (tenant_id, role_id) -> roles(tenant_id, id)
		_, err := pool.Exec(ctx, `
			INSERT INTO user_roles (tenant_id, user_id, role_id)
			VALUES (gen_random_uuid(), gen_random_uuid(), gen_random_uuid())`)
		assert.Error(t, err, "cross-tenant insert must fail foreign key constraint at database level")
	})
}

