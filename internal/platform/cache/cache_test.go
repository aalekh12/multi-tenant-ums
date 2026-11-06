package cache_test

import (
	"context"
	"testing"
	"time"

	"github.com/multi_tenante_ums/internal/platform/cache"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMemoryCache_GetSetDelete(t *testing.T) {
	ctx := context.Background()
	c := cache.NewMemory()

	// Get non-existent
	val, err := c.Get(ctx, "nonexistent")
	assert.Empty(t, val)
	assert.True(t, cache.IsNotFound(err))

	// Set value
	err = c.Set(ctx, "k1", "v1", 0)
	require.NoError(t, err)

	// Get value
	val, err = c.Get(ctx, "k1")
	require.NoError(t, err)
	assert.Equal(t, "v1", val)

	// Delete key
	err = c.Delete(ctx, "k1")
	require.NoError(t, err)

	val, err = c.Get(ctx, "k1")
	assert.Empty(t, val)
	assert.True(t, cache.IsNotFound(err))
}

func TestMemoryCache_Expiry(t *testing.T) {
	ctx := context.Background()
	c := cache.NewMemory()

	err := c.Set(ctx, "expKey", "val", 50*time.Millisecond)
	require.NoError(t, err)

	val, err := c.Get(ctx, "expKey")
	require.NoError(t, err)
	assert.Equal(t, "val", val)

	// Wait for expiration
	time.Sleep(60 * time.Millisecond)

	val, err = c.Get(ctx, "expKey")
	assert.Empty(t, val)
	assert.True(t, cache.IsNotFound(err))
}

func TestMemoryCache_Increment(t *testing.T) {
	ctx := context.Background()
	c := cache.NewMemory()

	n, err := c.Increment(ctx, "counter", time.Minute)
	require.NoError(t, err)
	assert.Equal(t, int64(1), n)

	n, err = c.Increment(ctx, "counter", time.Minute)
	require.NoError(t, err)
	assert.Equal(t, int64(2), n)

	n, err = c.Increment(ctx, "counter", time.Minute)
	require.NoError(t, err)
	assert.Equal(t, int64(3), n)
}

func TestMemoryCache_Ping(t *testing.T) {
	ctx := context.Background()
	c := cache.NewMemory()
	assert.NoError(t, c.Ping(ctx))
}
