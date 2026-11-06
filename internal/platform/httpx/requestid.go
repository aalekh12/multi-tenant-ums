package httpx

import (
	"context"
	"net/http"

	"github.com/go-chi/chi/v5/middleware"
)

type ctxKey int

const (
	ctxKeyRequestID ctxKey = iota
)

// RequestIDFromCtx returns the request ID from context or empty string.
func RequestIDFromCtx(ctx context.Context) string {
	// chi middleware stores request ID under its own key
	if id := middleware.GetReqID(ctx); id != "" {
		return id
	}
	return ""
}

// RequestIDMiddleware returns middleware that adds a request-id to each request.
// It delegates to chi's RequestID middleware.
func RequestIDMiddleware(next http.Handler) http.Handler {
	return middleware.RequestID(next)
}

