package middleware_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/multi_tenante_ums/internal/middleware"
	"github.com/stretchr/testify/assert"
)

type mockAuthValidator struct {
	authCtx middleware.AuthContext
	err     error
}

func (m *mockAuthValidator) ValidateToken(r *http.Request, tokenStr string) (middleware.AuthContext, error) {
	return m.authCtx, m.err
}

type mockTenantChecker struct {
	status string
	err    error
}

func (m *mockTenantChecker) GetStatus(ctx context.Context, tenantID string) (string, error) {
	return m.status, m.err
}

type mockPermissionResolver struct {
	has bool
	err error
}

func (m *mockPermissionResolver) HasPermission(ctx context.Context, tenantID, userID string, permCode string) (bool, error) {
	return m.has, m.err
}

func okHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
}

func TestAuthenticate_MissingHeader(t *testing.T) {
	v := &mockAuthValidator{}
	handler := middleware.Authenticate(v)(okHandler())

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.Equal(t, "Bearer", rec.Header().Get("WWW-Authenticate"))
}

func TestAuthenticate_MalformedHeader(t *testing.T) {
	v := &mockAuthValidator{}
	handler := middleware.Authenticate(v)(okHandler())

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Basic dXNlcjpwYXNz")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestAuthenticate_InvalidToken(t *testing.T) {
	v := &mockAuthValidator{err: errors.New("bad token")}
	handler := middleware.Authenticate(v)(okHandler())

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer invalid.token.value")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestAuthenticate_ValidToken_Success(t *testing.T) {
	expectedCtx := middleware.AuthContext{
		UserID:    "user-123",
		TenantID:  "tenant-456",
		SessionID: "sess-789",
	}
	v := &mockAuthValidator{authCtx: expectedCtx}

	var capturedCtx middleware.AuthContext
	captureHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedCtx = middleware.MustAuthContext(r.Context())
		w.WriteHeader(http.StatusOK)
	})

	handler := middleware.Authenticate(v)(captureHandler)

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer valid.token.value")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, expectedCtx, capturedCtx)
}

func TestTenantActive_Active_Success(t *testing.T) {
	checker := &mockTenantChecker{status: "active"}
	handler := middleware.TenantActive(checker)(okHandler())

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	ctx := middleware.WithAuthContext(req.Context(), middleware.AuthContext{TenantID: "tenant-1"})
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req.WithContext(ctx))

	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestTenantActive_Suspended_Returns403(t *testing.T) {
	checker := &mockTenantChecker{status: "suspended"}
	handler := middleware.TenantActive(checker)(okHandler())

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	ctx := middleware.WithAuthContext(req.Context(), middleware.AuthContext{TenantID: "tenant-1"})
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req.WithContext(ctx))

	assert.Equal(t, http.StatusForbidden, rec.Code)
}

func TestRequirePermission_HasPermission_Success(t *testing.T) {
	resolver := &mockPermissionResolver{has: true}
	handler := middleware.RequirePermission(resolver, "user:create")(okHandler())

	req := httptest.NewRequest(http.MethodPost, "/users", nil)
	ctx := middleware.WithAuthContext(req.Context(), middleware.AuthContext{TenantID: "tenant-1", UserID: "user-1"})
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req.WithContext(ctx))

	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestRequirePermission_LacksPermission_Returns403(t *testing.T) {
	resolver := &mockPermissionResolver{has: false}
	handler := middleware.RequirePermission(resolver, "user:delete")(okHandler())

	req := httptest.NewRequest(http.MethodDelete, "/users/123", nil)
	ctx := middleware.WithAuthContext(req.Context(), middleware.AuthContext{TenantID: "tenant-1", UserID: "user-1"})
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req.WithContext(ctx))

	assert.Equal(t, http.StatusForbidden, rec.Code)
}
