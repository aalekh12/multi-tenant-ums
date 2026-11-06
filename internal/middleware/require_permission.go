package middleware

import (
	"context"
	"net/http"

	"github.com/yourusername/usermgmt/internal/platform/httpx"
)

// PermissionResolver resolves a user's permission codes for a tenant.
type PermissionResolver interface {
	HasPermission(ctx context.Context, tenantID, userID string, permCode string) (bool, error)
}

// RequirePermission returns middleware that checks if the authenticated user
// holds the required permission. Must run after Authenticate.
func RequirePermission(resolver PermissionResolver, permCode string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			auth, ok := AuthContextFromCtx(r.Context())
			if !ok {
				w.Header().Set("WWW-Authenticate", "Bearer")
				httpx.WriteError(w, r, http.StatusUnauthorized, httpx.ErrCodeUnauthenticated, "authentication required")
				return
			}

			has, err := resolver.HasPermission(r.Context(), auth.TenantID, auth.UserID, permCode)
			if err != nil {
				httpx.WriteError(w, r, http.StatusInternalServerError, httpx.ErrCodeInternal, "permission check failed")
				return
			}
			if !has {
				httpx.WriteError(w, r, http.StatusForbidden, httpx.ErrCodeForbidden,
					"permission denied",
					httpx.FieldError{Field: "permission", Issue: "requires " + permCode},
				)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

