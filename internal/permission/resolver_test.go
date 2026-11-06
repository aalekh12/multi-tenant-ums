package permission_test

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/multi_tenante_ums/internal/permission"
	"github.com/multi_tenante_ums/internal/platform/cache"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockPermGetter struct {
	callCount int64
	perms     []string
	err       error
}

func (m *mockPermGetter) GetUserPermissions(ctx context.Context, tenantID, userID string) ([]string, error) {
	atomic.AddInt64(&m.callCount, 1)
	return m.perms, m.err
}

func TestResolver_CacheHitAndMiss(t *testing.T) {
	ctx := context.Background()
	c := cache.NewMemory()
	getter := &mockPermGetter{perms: []string{"user:read", "user:create"}}

	res := permission.NewResolver(getter, c, 5*time.Minute)

	// First call - cache miss, should hit repo
	codes, err := res.Get(ctx, "tenant-1", "user-1")
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{"user:read", "user:create"}, codes)
	assert.Equal(t, int64(1), atomic.LoadInt64(&getter.callCount))

	// Second call - cache hit, repo should NOT be called again
	codes, err = res.Get(ctx, "tenant-1", "user-1")
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{"user:read", "user:create"}, codes)
	assert.Equal(t, int64(1), atomic.LoadInt64(&getter.callCount))

	// HasPermission check
	has, err := res.HasPermission(ctx, "tenant-1", "user-1", "user:read")
	require.NoError(t, err)
	assert.True(t, has)

	has, err = res.HasPermission(ctx, "tenant-1", "user-1", "user:delete")
	require.NoError(t, err)
	assert.False(t, has)
	assert.Equal(t, int64(1), atomic.LoadInt64(&getter.callCount))
}

func TestResolver_Invalidation(t *testing.T) {
	ctx := context.Background()
	c := cache.NewMemory()
	getter := &mockPermGetter{perms: []string{"user:read"}}

	res := permission.NewResolver(getter, c, 5*time.Minute)

	_, err := res.Get(ctx, "tenant-1", "user-1")
	require.NoError(t, err)
	assert.Equal(t, int64(1), atomic.LoadInt64(&getter.callCount))

	// Invalidate user cache
	res.InvalidateUser(ctx, "tenant-1", "user-1")

	// Next call should query repo again
	_, err = res.Get(ctx, "tenant-1", "user-1")
	require.NoError(t, err)
	assert.Equal(t, int64(2), atomic.LoadInt64(&getter.callCount))
}

func TestResolver_DBError_NeverAllows(t *testing.T) {
	ctx := context.Background()
	c := cache.NewMemory()
	getter := &mockPermGetter{err: errors.New("db failure")}

	res := permission.NewResolver(getter, c, 5*time.Minute)

	has, err := res.HasPermission(ctx, "tenant-1", "user-1", "user:read")
	require.Error(t, err)
	assert.False(t, has, "must fail closed to false on error, never allow")
}
