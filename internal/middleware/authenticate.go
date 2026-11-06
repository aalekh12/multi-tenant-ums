package middleware

import (
	"net/http"
	"strings"

	"github.com/multi_tenante_ums/internal/platform/httpx"
	"github.com/multi_tenante_ums/internal/platform/jwtx"
)

// AuthValidator validates tokens and checks membership/user status.
type AuthValidator interface {
	ValidateToken(r *http.Request, tokenStr string) (AuthContext, error)
}

// Authenticate reads the Bearer token, validates it, and stores AuthContext.
func Authenticate(validator AuthValidator) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
				w.Header().Set("WWW-Authenticate", "Bearer")
				httpx.WriteError(w, r, http.StatusUnauthorized, httpx.ErrCodeUnauthenticated, "authentication required")
				return
			}
			tokenStr := strings.TrimPrefix(authHeader, "Bearer ")
			authCtx, err := validator.ValidateToken(r, tokenStr)
			if err != nil {
				w.Header().Set("WWW-Authenticate", "Bearer")
				// Check if it's a suspension error
				if err.Error() == "TENANT_SUSPENDED" {
					httpx.WriteError(w, r, http.StatusForbidden, httpx.ErrCodeTenantSuspended, "tenant is suspended")
					return
				}
				httpx.WriteError(w, r, http.StatusUnauthorized, httpx.ErrCodeUnauthenticated, "invalid or expired token")
				return
			}
			ctx := WithAuthContext(r.Context(), authCtx)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// ErrInvalidToken is re-exported for use by AuthValidator implementations.
var ErrInvalidToken = jwtx.ErrInvalidToken
