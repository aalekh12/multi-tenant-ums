package jwtx_test

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/yourusername/usermgmt/internal/platform/jwtx"
)

func newTestIssuer() *jwtx.Issuer {
	return jwtx.New(jwtx.Config{
		Secret:   []byte("test-super-secret-key-at-least-32-bytes!"),
		Kid:      "v1",
		Issuer:   "usermgmt-test",
		Audience: "usermgmt-test-api",
	})
}

func TestIssuer_IssueAndParse_Success(t *testing.T) {
	iss := newTestIssuer()
	userID := uuid.New().String()
	tenantID := uuid.New().String()
	sessionID := uuid.New().String()

	// Access token
	tokenStr, jti, err := iss.IssueAccess(userID, tenantID, sessionID, 15*time.Minute)
	require.NoError(t, err)
	assert.NotEmpty(t, tokenStr)
	assert.NotEmpty(t, jti)

	claims, err := iss.Parse(tokenStr, jwtx.TypeAccess)
	require.NoError(t, err)
	assert.Equal(t, userID, claims.Subject)
	assert.Equal(t, tenantID, claims.TenantID)
	assert.Equal(t, sessionID, claims.SessionID)
	assert.Equal(t, jti, claims.ID)
	assert.Equal(t, jwtx.TypeAccess, claims.Type)

	// Refresh token
	refreshJTI := uuid.New().String()
	refreshTokenStr, err := iss.IssueRefresh(userID, tenantID, sessionID, refreshJTI, 24*time.Hour)
	require.NoError(t, err)
	assert.NotEmpty(t, refreshTokenStr)

	refreshClaims, err := iss.Parse(refreshTokenStr, jwtx.TypeRefresh)
	require.NoError(t, err)
	assert.Equal(t, userID, refreshClaims.Subject)
	assert.Equal(t, tenantID, refreshClaims.TenantID)
	assert.Equal(t, sessionID, refreshClaims.SessionID)
	assert.Equal(t, refreshJTI, refreshClaims.ID)
	assert.Equal(t, jwtx.TypeRefresh, refreshClaims.Type)
}

func TestIssuer_ExpiredToken_Rejected(t *testing.T) {
	iss := newTestIssuer()
	userID := uuid.New().String()
	tenantID := uuid.New().String()
	sessionID := uuid.New().String()

	tokenStr, _, err := iss.IssueAccess(userID, tenantID, sessionID, -1*time.Minute)
	require.NoError(t, err)

	_, err = iss.Parse(tokenStr, jwtx.TypeAccess)
	require.Error(t, err)
	assert.ErrorIs(t, err, jwtx.ErrInvalidToken)
}

func TestIssuer_WrongType_Rejected(t *testing.T) {
	iss := newTestIssuer()
	userID := uuid.New().String()
	tenantID := uuid.New().String()
	sessionID := uuid.New().String()

	tokenStr, _, err := iss.IssueAccess(userID, tenantID, sessionID, 15*time.Minute)
	require.NoError(t, err)

	_, err = iss.Parse(tokenStr, jwtx.TypeRefresh)
	require.Error(t, err)
	assert.ErrorIs(t, err, jwtx.ErrInvalidToken)
}

func TestIssuer_TamperedSignature_Rejected(t *testing.T) {
	iss := newTestIssuer()
	userID := uuid.New().String()
	tenantID := uuid.New().String()
	sessionID := uuid.New().String()

	tokenStr, _, err := iss.IssueAccess(userID, tenantID, sessionID, 15*time.Minute)
	require.NoError(t, err)

	// Tamper signature
	tampered := tokenStr[:len(tokenStr)-4] + "xxxx"
	_, err = iss.Parse(tampered, jwtx.TypeAccess)
	require.Error(t, err)
	assert.ErrorIs(t, err, jwtx.ErrInvalidToken)
}

func TestIssuer_WrongAlgorithm_None_Rejected(t *testing.T) {
	iss := newTestIssuer()

	claims := jwtx.Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        uuid.New().String(),
			Subject:   uuid.New().String(),
			Issuer:    "usermgmt-test",
			Audience:  jwt.ClaimStrings{"usermgmt-test-api"},
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(15 * time.Minute)),
		},
		TenantID:  uuid.New().String(),
		SessionID: uuid.New().String(),
		Type:      jwtx.TypeAccess,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodNone, claims)
	tokenStr, err := token.SignedString(jwt.UnsafeAllowNoneSignatureType)
	require.NoError(t, err)

	_, err = iss.Parse(tokenStr, jwtx.TypeAccess)
	require.Error(t, err)
	assert.ErrorIs(t, err, jwtx.ErrInvalidToken)
}

func TestIssuer_WrongAlgorithm_RS256_Rejected(t *testing.T) {
	iss := newTestIssuer()

	claims := jwtx.Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        uuid.New().String(),
			Subject:   uuid.New().String(),
			Issuer:    "usermgmt-test",
			Audience:  jwt.ClaimStrings{"usermgmt-test-api"},
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(15 * time.Minute)),
		},
		TenantID:  uuid.New().String(),
		SessionID: uuid.New().String(),
		Type:      jwtx.TypeAccess,
	}

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tokenStr, err := token.SignedString(rsaKey)
	require.NoError(t, err)

	_, err = iss.Parse(tokenStr, jwtx.TypeAccess)
	require.Error(t, err)
	assert.ErrorIs(t, err, jwtx.ErrInvalidToken)
}

func TestIssuer_MissingClaims_Rejected(t *testing.T) {
	secret := []byte("test-super-secret-key-at-least-32-bytes!")
	iss := jwtx.New(jwtx.Config{
		Secret:   secret,
		Kid:      "v1",
		Issuer:   "usermgmt-test",
		Audience: "usermgmt-test-api",
	})

	// Missing TenantID (tid)
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwtx.Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        uuid.New().String(),
			Subject:   uuid.New().String(),
			Issuer:    "usermgmt-test",
			Audience:  jwt.ClaimStrings{"usermgmt-test-api"},
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(15 * time.Minute)),
		},
		SessionID: uuid.New().String(),
		Type:      jwtx.TypeAccess,
	})
	tokenStr, err := token.SignedString(secret)
	require.NoError(t, err)

	_, err = iss.Parse(tokenStr, jwtx.TypeAccess)
	require.Error(t, err)
	assert.ErrorIs(t, err, jwtx.ErrInvalidToken)
}

