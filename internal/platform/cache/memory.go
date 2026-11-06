package cache

import (
	"context"
	"sync"
	"time"
)

type memEntry struct {
	value     string
	expiresAt time.Time // zero means no expiry
}

// Memory is a thread-safe in-memory cache implementation.
type Memory struct {
	mu      sync.RWMutex
	entries map[string]memEntry
	counts  map[string]int64
	countExpiry map[string]time.Time
}

// NewMemory returns a new in-memory cache.
func NewMemory() *Memory {
	return &Memory{
		entries:     make(map[string]memEntry),
		counts:      make(map[string]int64),
		countExpiry: make(map[string]time.Time),
	}
}

func (m *Memory) Get(ctx context.Context, key string) (string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	e, ok := m.entries[key]
	if !ok {
		return "", &ErrNotFound{Key: key}
	}
	if !e.expiresAt.IsZero() && time.Now().After(e.expiresAt) {
		return "", &ErrNotFound{Key: key}
	}
	return e.value, nil
}

func (m *Memory) Set(ctx context.Context, key string, value string, ttl time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	var exp time.Time
	if ttl > 0 {
		exp = time.Now().Add(ttl)
	}
	m.entries[key] = memEntry{value: value, expiresAt: exp}
	return nil
}

func (m *Memory) Delete(ctx context.Context, keys ...string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, k := range keys {
		delete(m.entries, k)
		delete(m.counts, k)
		delete(m.countExpiry, k)
	}
	return nil
}

func (m *Memory) Increment(ctx context.Context, key string, ttl time.Duration) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()
	if exp, ok := m.countExpiry[key]; ok && now.After(exp) {
		delete(m.counts, key)
		delete(m.countExpiry, key)
	}

	m.counts[key]++
	if _, exists := m.countExpiry[key]; !exists && ttl > 0 {
		m.countExpiry[key] = now.Add(ttl)
	}
	return m.counts[key], nil
}

func (m *Memory) Ping(ctx context.Context) error { return nil }

