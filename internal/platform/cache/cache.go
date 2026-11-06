// Package cache provides a Cache interface with Redis and in-memory implementations.
package cache

import (
	"context"
	"time"
)

// Cache is the interface implemented by all cache backends.
type Cache interface {
	// Get retrieves the value for key. Returns ("", ErrNotFound) if absent.
	Get(ctx context.Context, key string) (string, error)
	// Set stores value with TTL (0 means no expiry).
	Set(ctx context.Context, key string, value string, ttl time.Duration) error
	// Delete removes one or more keys. Missing keys are silently ignored.
	Delete(ctx context.Context, keys ...string) error
	// Increment atomically increments the integer stored at key and applies TTL
	// only when the key is first created. Returns the new value.
	Increment(ctx context.Context, key string, ttl time.Duration) (int64, error)
	// Ping checks connectivity to the cache backend.
	Ping(ctx context.Context) error
}

// ErrNotFound is returned when a key does not exist in the cache.
type ErrNotFound struct{ Key string }

func (e *ErrNotFound) Error() string { return "cache: key not found: " + e.Key }

// IsNotFound returns true if err is an ErrNotFound.
func IsNotFound(err error) bool {
	if err == nil {
		return false
	}
	_, ok := err.(*ErrNotFound)
	return ok
}

