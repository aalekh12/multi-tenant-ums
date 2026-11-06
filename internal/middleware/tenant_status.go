package middleware

import (
	"context"
	"net/http"

	"github.com/yourusername/usermgmt/internal/platform/httpx"
)

// TenantChecker verifies the operational status of a tenant.
type TenantChecker interface {
	GetStatus(ctx context.Context, tenantID string) (string, error)
}

// TenantActive returns middleware that verifies the token's tenant is active.
// Returns 403 TENANT_SUSPENDED if the tenant is suspended.
func TenantActive(checker TenantChecker) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			auth, ok := AuthContextFromCtx(r.Context())
			if !ok {
				w.Header().Set("WWW-Authenticate", "Bearer")
				httpx.WriteError(w, r, http.StatusUnauthorized, httpx.ErrCodeUnauthenticated, "authentication required")
				return
			}

			status, err := checker.GetStatus(r.Context(), auth.TenantID)
			if err != nil {
				httpx.WriteError(w, r, http.StatusUnauthorized, httpx.ErrCodeUnauthenticated, "invalid tenant")
				return
			}

			if status == "suspended" {
				httpx.WriteError(w, r, http.StatusForbidden, httpx.ErrCodeTenantSuspended, "tenant is suspended")
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

