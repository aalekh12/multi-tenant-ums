package integration_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/multi_tenante_ums/internal/api"
	"github.com/multi_tenante_ums/internal/config"
	"github.com/multi_tenante_ums/internal/platform/cache"
	"github.com/multi_tenante_ums/internal/platform/jwtx"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestConfig() *config.Config {
	return &config.Config{
		HTTPAddr:            ":8080",
		JWTSecret:           "super-secret-key-at-least-32-bytes-long!",
		JWTKid:              "v1",
		JWTIssuer:           "multi_tenant_ums",
		JWTAudience:         "multi_tenant_ums-api",
		AccessTTL:           15 * time.Minute,
		RefreshTTL:          24 * time.Hour,
		PermCacheTTL:        5 * time.Minute,
		TenantCacheTTL:      30 * time.Second,
		DBHealthCheckPeriod: 5 * time.Second,
		BcryptCost:          4, // minimum cost for fast tests
	}
}

// TestUnknownFieldInBody_Returns400 verifies Decision 6:
// If a body contains "tenant_id", reject with 400 (UNKNOWN_FIELD; decoder uses DisallowUnknownFields).
func TestUnknownFieldInBody_Returns400(t *testing.T) {
	cfg := newTestConfig()
	c := cache.NewMemory()

	// Build router (pool is nil for routing & decode-level testing)
	// We test against an endpoint with body decoding
	issuer := jwtx.New(jwtx.Config{
		Secret:   []byte(cfg.JWTSecret),
		Kid:      cfg.JWTKid,
		Issuer:   cfg.JWTIssuer,
		Audience: cfg.JWTAudience,
	})

	tid := uuid.New().String()
	uid := uuid.New().String()
	token, _, err := issuer.IssueAccess(uid, tid, uuid.New().String(), 15*time.Minute)
	require.NoError(t, err)

	// Pre-populate tenant status so TenantActive middleware passes
	_ = c.Set(context.Background(), "tenant:status:"+tid, "active", 30*time.Second)

	// Pre-populate permissions for "user:create" so RequirePermission passes
	_ = c.Set(context.Background(), "perm:"+tid+":"+uid, "[\"user:create\"]", 5*time.Minute)

	// Send POST /api/v1/users with forbidden "tenant_id" field in JSON body
	body := map[string]any{
		"email":     "hacker@example.com",
		"full_name": "Hacker",
		"password":  "P@ssword123",
		"tenant_id": uuid.New().String(), // Forbidden injected field!
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/users", bytes.NewBuffer(bodyBytes))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	r := api.NewRouter(cfg, nil, c)
	r.ServeHTTP(rec, req)

	// Must be rejected with 400 Bad Request
	assert.Equal(t, http.StatusBadRequest, rec.Code)

	var errResp struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &errResp)
	assert.Equal(t, "UNKNOWN_FIELD", errResp.Error.Code)
}

// TestForgedTIDClaim_InvalidSignature_Returns401 verifies:
// Modifying or forging the tid claim in a JWT fails signature verification -> returns 401.
func TestForgedTIDClaim_InvalidSignature_Returns401(t *testing.T) {
	cfg := newTestConfig()
	c := cache.NewMemory()

	// Token issued with valid secret
	issuer := jwtx.New(jwtx.Config{
		Secret:   []byte(cfg.JWTSecret),
		Kid:      cfg.JWTKid,
		Issuer:   cfg.JWTIssuer,
		Audience: cfg.JWTAudience,
	})
	token, _, err := issuer.IssueAccess(uuid.New().String(), uuid.New().String(), uuid.New().String(), 15*time.Minute)
	require.NoError(t, err)

	// Forged token: sign with wrong secret
	fakeIssuer := jwtx.New(jwtx.Config{
		Secret:   []byte("wrong-attacker-secret-at-least-32-bytes!"),
		Kid:      cfg.JWTKid,
		Issuer:   cfg.JWTIssuer,
		Audience: cfg.JWTAudience,
	})
	forgedToken, _, err := fakeIssuer.IssueAccess(uuid.New().String(), uuid.New().String(), uuid.New().String(), 15*time.Minute)
	require.NoError(t, err)

	r := api.NewRouter(cfg, nil, c)

	// Request with forged token
	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/me", nil)
	req.Header.Set("Authorization", "Bearer "+forgedToken)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.Equal(t, "Bearer", rec.Header().Get("WWW-Authenticate"))

	_ = token
}

// Test401Vs403_Behavior verifies Section 7:
// Missing/bad token -> 401 UNAUTHENTICATED
// Valid token without permission -> 403 FORBIDDEN
// Valid token in suspended tenant -> 403 TENANT_SUSPENDED
func Test401Vs403_Behavior(t *testing.T) {
	cfg := newTestConfig()
	c := cache.NewMemory()
	r := api.NewRouter(cfg, nil, c)

	issuer := jwtx.New(jwtx.Config{
		Secret:   []byte(cfg.JWTSecret),
		Kid:      cfg.JWTKid,
		Issuer:   cfg.JWTIssuer,
		Audience: cfg.JWTAudience,
	})

	// 1. Missing header -> 401
	req1 := httptest.NewRequest(http.MethodGet, "/api/v1/tenant", nil)
	rec1 := httptest.NewRecorder()
	r.ServeHTTP(rec1, req1)
	assert.Equal(t, http.StatusUnauthorized, rec1.Code)

	// 2. Token in suspended tenant -> 403 TENANT_SUSPENDED
	tidSuspended := uuid.New().String()
	tokenSuspended, _, _ := issuer.IssueAccess(uuid.New().String(), tidSuspended, uuid.New().String(), 15*time.Minute)
	_ = c.Set(context.Background(), "tenant:status:"+tidSuspended, "suspended", 30*time.Second)

	req2 := httptest.NewRequest(http.MethodGet, "/api/v1/tenant", nil)
	req2.Header.Set("Authorization", "Bearer "+tokenSuspended)
	rec2 := httptest.NewRecorder()
	r.ServeHTTP(rec2, req2)
	assert.Equal(t, http.StatusForbidden, rec2.Code)

	var errResp2 struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	_ = json.Unmarshal(rec2.Body.Bytes(), &errResp2)
	assert.Equal(t, "TENANT_SUSPENDED", errResp2.Error.Code)

	// 3. Authenticated in active tenant but lacking permission -> 403 FORBIDDEN
	tidActive := uuid.New().String()
	uid := uuid.New().String()
	tokenActive, _, _ := issuer.IssueAccess(uid, tidActive, uuid.New().String(), 15*time.Minute)
	_ = c.Set(context.Background(), "tenant:status:"+tidActive, "active", 30*time.Second)
	// Permissions cached as empty list (holds no permissions)
	_ = c.Set(context.Background(), "perm:"+tidActive+":"+uid, "[]", 5*time.Minute)

	req3 := httptest.NewRequest(http.MethodGet, "/api/v1/tenant", nil)
	req3.Header.Set("Authorization", "Bearer "+tokenActive)
	rec3 := httptest.NewRecorder()
	r.ServeHTTP(rec3, req3)
	assert.Equal(t, http.StatusForbidden, rec3.Code)

	var errResp3 struct {
		Error struct {
			Code    string `json:"code"`
			Details []struct {
				Field string `json:"field"`
				Issue string `json:"issue"`
			} `json:"details"`
		} `json:"error"`
	}
	_ = json.Unmarshal(rec3.Body.Bytes(), &errResp3)
	assert.Equal(t, "FORBIDDEN", errResp3.Error.Code)
	require.NotEmpty(t, errResp3.Error.Details)
	assert.Contains(t, errResp3.Error.Details[0].Issue, "requires tenant:read")
}

// TestMalformedUUID_Returns404 verifies Section 8:
// Path ids that fail UUID parsing -> 404 (not 400) on resource routes, to avoid probing.
func TestMalformedUUID_Returns404(t *testing.T) {
	cfg := newTestConfig()
	c := cache.NewMemory()
	r := api.NewRouter(cfg, nil, c)

	issuer := jwtx.New(jwtx.Config{
		Secret:   []byte(cfg.JWTSecret),
		Kid:      cfg.JWTKid,
		Issuer:   cfg.JWTIssuer,
		Audience: cfg.JWTAudience,
	})

	tid := uuid.New().String()
	uid := uuid.New().String()
	token, _, _ := issuer.IssueAccess(uid, tid, uuid.New().String(), 15*time.Minute)

	_ = c.Set(context.Background(), "tenant:status:"+tid, "active", 30*time.Second)
	// Grant all permissions
	_ = c.Set(context.Background(), "perm:"+tid+":"+uid, "[\"user:read\",\"role:read\",\"tenant:read\"]", 5*time.Minute)

	// Probe with malformed IDs
	probePaths := []string{
		"/api/v1/users/not-a-valid-uuid",
		"/api/v1/users/123",
		"/api/v1/roles/invalid_uuid_string",
		"/api/v1/roles/1",
	}

	for _, path := range probePaths {
		t.Run(path, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, path, nil)
			req.Header.Set("Authorization", "Bearer "+token)
			rec := httptest.NewRecorder()
			r.ServeHTTP(rec, req)

			assert.Equal(t, http.StatusNotFound, rec.Code, "probing path %s must return 404, not 400", path)
		})
	}
}
