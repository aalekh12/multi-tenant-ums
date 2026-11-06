package password_test

import (
	"strings"
	"testing"

	"github.com/multi_tenante_ums/internal/platform/password"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
)

func TestHasher_HashAndCompare(t *testing.T) {
	hasher := password.New(bcrypt.MinCost)

	pwd := "MySecureP@ss123"
	hash, err := hasher.Hash(pwd)
	require.NoError(t, err)
	assert.NotEmpty(t, hash)

	// Correct password
	err = hasher.Compare(hash, pwd)
	assert.NoError(t, err)

	// Wrong password
	err = hasher.Compare(hash, "WrongPassword999")
	assert.ErrorIs(t, err, password.ErrMismatch)
}

func TestHasher_LongPassword_Over72Bytes(t *testing.T) {
	hasher := password.New(bcrypt.MinCost)

	// 100 character password
	longPwd := strings.Repeat("a", 100) + "123"
	hash, err := hasher.Hash(longPwd)
	require.NoError(t, err)

	// Must compare successfully with identical long password
	err = hasher.Compare(hash, longPwd)
	assert.NoError(t, err)

	// Must also match truncated 72-byte prefix because bcrypt truncates at 72 bytes
	err = hasher.Compare(hash, longPwd[:72])
	assert.NoError(t, err)

	// Must not match different password
	err = hasher.Compare(hash, strings.Repeat("b", 100))
	assert.ErrorIs(t, err, password.ErrMismatch)
}

func TestHasher_DummyHash(t *testing.T) {
	hasher := password.New(bcrypt.MinCost)

	// Compare with dummy hash should return ErrMismatch
	err := hasher.Compare(password.DummyHash, "anyPassword123")
	assert.ErrorIs(t, err, password.ErrMismatch)
}

func TestHasher_CostBounds(t *testing.T) {
	// Out of bounds cost falls back to DefaultCost
	hLow := password.New(1)
	assert.NotNil(t, hLow)

	hHigh := password.New(99)
	assert.NotNil(t, hHigh)
}
