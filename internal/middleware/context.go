// Package middleware provides HTTP middleware for the API.
package middleware

import (
	"context"
	"net/http"
)

// authCtxKey is the context key for AuthContext.
type authCtxKey struct{}

// AuthContext holds the authenticated identity extracted from the JWT.
type AuthContext struct {
	UserID    string
	TenantID  string
	SessionID string
}

// WithAuthContext stores an AuthContext in the context.
func WithAuthContext(ctx context.Context, auth AuthContext) context.Context {
	return context.WithValue(ctx, authCtxKey{}, auth)
}

// AuthContextFromCtx retrieves the AuthContext from the context.
// Returns zero value and false if not present.
func AuthContextFromCtx(ctx context.Context) (AuthContext, bool) {
	v, ok := ctx.Value(authCtxKey{}).(AuthContext)
	return v, ok
}

// MustAuthContext retrieves the AuthContext or panics (use only after Authenticate middleware).
func MustAuthContext(ctx context.Context) AuthContext {
	v, ok := AuthContextFromCtx(ctx)
	if !ok {
		panic("middleware: auth context missing from context")
	}
	return v
}

// TenantIDFromCtx returns the tenant ID from context.
func TenantIDFromCtx(ctx context.Context) string {
	a, _ := AuthContextFromCtx(ctx)
	return a.TenantID
}

// UserIDFromCtx returns the user ID from context.
func UserIDFromCtx(ctx context.Context) string {
	a, _ := AuthContextFromCtx(ctx)
	return a.UserID
}

// Recover is a middleware that recovers from panics and returns 500.
func Recover(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				http.Error(w, `{"error":{"code":"INTERNAL_ERROR","message":"internal server error"}}`, http.StatusInternalServerError)
			}
		}()
		next.ServeHTTP(w, r)
	})
}

