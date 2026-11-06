// Package jwtx provides JWT issue and parse helpers for HS256 access and refresh tokens.
package jwtx

import (
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

const (
	TypeAccess  = "access"
	TypeRefresh = "refresh"
)

// Claims is the custom JWT claims struct.
type Claims struct {
	jwt.RegisteredClaims
	TenantID  string `json:"tid"`
	SessionID string `json:"sid"`
	Type      string `json:"typ"`
}

// Config holds the parameters used by Issuer.
type Config struct {
	Secret   []byte
	Kid      string
	Issuer   string
	Audience string
}

// Issuer issues and parses JWTs.
type Issuer struct {
	cfg Config
}

// New returns a new Issuer.
func New(cfg Config) *Issuer {
	return &Issuer{cfg: cfg}
}

// IssueAccess creates a signed access token.
func (iss *Issuer) IssueAccess(userID, tenantID, sessionID string, ttl time.Duration) (string, string, error) {
	return iss.issue(TypeAccess, userID, tenantID, sessionID, ttl)
}

// IssueRefresh creates a signed refresh token.
func (iss *Issuer) IssueRefresh(userID, tenantID, sessionID string, jti string, ttl time.Duration) (string, error) {
	claims := Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        jti,
			Subject:   userID,
			Issuer:    iss.cfg.Issuer,
			Audience:  jwt.ClaimStrings{iss.cfg.Audience},
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(ttl)),
		},
		TenantID:  tenantID,
		SessionID: sessionID,
		Type:      TypeRefresh,
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	token.Header["kid"] = iss.cfg.Kid
	signed, err := token.SignedString(iss.cfg.Secret)
	if err != nil {
		return "", fmt.Errorf("jwtx: sign refresh: %w", err)
	}
	return signed, nil
}

func (iss *Issuer) issue(typ, userID, tenantID, sessionID string, ttl time.Duration) (string, string, error) {
	jti := uuid.New().String()
	claims := Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        jti,
			Subject:   userID,
			Issuer:    iss.cfg.Issuer,
			Audience:  jwt.ClaimStrings{iss.cfg.Audience},
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(ttl)),
		},
		TenantID:  tenantID,
		SessionID: sessionID,
		Type:      typ,
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	token.Header["kid"] = iss.cfg.Kid
	signed, err := token.SignedString(iss.cfg.Secret)
	if err != nil {
		return "", "", fmt.Errorf("jwtx: sign: %w", err)
	}
	return signed, jti, nil
}

// ErrInvalidToken is returned when a token is invalid for any reason.
var ErrInvalidToken = errors.New("jwtx: invalid token")

// Parse validates the token string and returns its claims.
// It enforces: HS256 only, correct iss/aud, expected typ.
func (iss *Issuer) Parse(tokenStr, expectedType string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenStr, &Claims{}, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("jwtx: unexpected signing method: %v", t.Header["alg"])
		}
		return iss.cfg.Secret, nil
	}, jwt.WithValidMethods([]string{"HS256"}),
		jwt.WithIssuer(iss.cfg.Issuer),
		jwt.WithAudience(iss.cfg.Audience),
		jwt.WithExpirationRequired(),
	)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidToken, err)
	}

	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return nil, ErrInvalidToken
	}

	if claims.Type != expectedType {
		return nil, fmt.Errorf("%w: expected typ=%q got %q", ErrInvalidToken, expectedType, claims.Type)
	}
	if claims.TenantID == "" {
		return nil, fmt.Errorf("%w: missing tid claim", ErrInvalidToken)
	}
	if claims.SessionID == "" {
		return nil, fmt.Errorf("%w: missing sid claim", ErrInvalidToken)
	}

	return claims, nil
}

