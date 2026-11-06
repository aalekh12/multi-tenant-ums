// Package password wraps bcrypt operations.
package password

import (
	"errors"
	"fmt"

	"golang.org/x/crypto/bcrypt"
)

// ErrMismatch is returned when a password does not match its hash.
var ErrMismatch = errors.New("password: mismatch")

// Hasher hashes and compares passwords.
type Hasher struct {
	cost int
}

// New returns a Hasher with the given bcrypt cost.
func New(cost int) *Hasher {
	if cost < bcrypt.MinCost || cost > bcrypt.MaxCost {
		cost = bcrypt.DefaultCost
	}
	return &Hasher{cost: cost}
}

// Hash returns the bcrypt hash of password. The input is truncated to 72 bytes
// to match bcrypt's effective limit.
func (h *Hasher) Hash(password string) (string, error) {
	b := []byte(password)
	if len(b) > 72 {
		b = b[:72]
	}
	hash, err := bcrypt.GenerateFromPassword(b, h.cost)
	if err != nil {
		return "", fmt.Errorf("password: hash: %w", err)
	}
	return string(hash), nil
}

// Compare returns nil if password matches hash, ErrMismatch otherwise.
func (h *Hasher) Compare(hash, password string) error {
	b := []byte(password)
	if len(b) > 72 {
		b = b[:72]
	}
	err := bcrypt.CompareHashAndPassword([]byte(hash), b)
	if errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
		return ErrMismatch
	}
	if err != nil {
		return fmt.Errorf("password: compare: %w", err)
	}
	return nil
}

// DummyHash is a precomputed hash used to equalize timing when user is not found.
// Generated with cost 10 to avoid slowing tests.
const DummyHash = "$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy"

