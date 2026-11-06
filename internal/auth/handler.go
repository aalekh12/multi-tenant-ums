package auth

import (
	"net/http"

	"github.com/yourusername/usermgmt/internal/middleware"
	"github.com/yourusername/usermgmt/internal/permission"
	"github.com/yourusername/usermgmt/internal/platform/httpx"
	"github.com/yourusername/usermgmt/internal/platform/validate"
)

// Handler is the HTTP handler for auth routes.
type Handler struct {
	svc      *Service
	resolver *permission.Resolver
}

// NewHandler creates a new auth Handler.
func NewHandler(svc *Service, resolver *permission.Resolver) *Handler {
	return &Handler{svc: svc, resolver: resolver}
}

// Login handles POST /api/v1/auth/login.
func (h *Handler) Login(w http.ResponseWriter, r *http.Request) {
	var in LoginInput
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteDecodeError(w, r, err)
		return
	}
	if err := validate.Get().Struct(&in); err != nil {
		httpx.WriteValidationError(w, r, err)
		return
	}

	pair, err := h.svc.Login(r.Context(), r, &in)
	if err != nil {
		switch err {
		case ErrRateLimit:
			httpx.WriteError(w, r, http.StatusTooManyRequests, httpx.ErrCodeRateLimited, "too many login attempts, try again later")
		case ErrTenantSuspended:
			httpx.WriteError(w, r, http.StatusForbidden, httpx.ErrCodeTenantSuspended, "tenant is suspended")
		default:
			httpx.WriteError(w, r, http.StatusUnauthorized, httpx.ErrCodeInvalidCredentials, "invalid credentials")
		}
		return
	}
	httpx.WriteJSON(w, http.StatusOK, httpx.DataResponse[*TokenPair]{Data: pair})
}

// Refresh handles POST /api/v1/auth/refresh.
func (h *Handler) Refresh(w http.ResponseWriter, r *http.Request) {
	var in RefreshInput
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteDecodeError(w, r, err)
		return
	}
	if err := validate.Get().Struct(&in); err != nil {
		httpx.WriteValidationError(w, r, err)
		return
	}

	pair, err := h.svc.Refresh(r.Context(), r, in.RefreshToken)
	if err != nil {
		switch err {
		case ErrTenantSuspended:
			httpx.WriteError(w, r, http.StatusForbidden, httpx.ErrCodeTenantSuspended, "tenant is suspended")
		case ErrRefreshReuse:
			httpx.WriteError(w, r, http.StatusUnauthorized, httpx.ErrCodeUnauthenticated, "refresh token reuse detected; session revoked")
		default:
			httpx.WriteError(w, r, http.StatusUnauthorized, httpx.ErrCodeUnauthenticated, "invalid or expired refresh token")
		}
		return
	}
	httpx.WriteJSON(w, http.StatusOK, httpx.DataResponse[*TokenPair]{Data: pair})
}

// Logout handles POST /api/v1/auth/logout.
func (h *Handler) Logout(w http.ResponseWriter, r *http.Request) {
	auth := middleware.MustAuthContext(r.Context())
	if err := h.svc.Logout(r.Context(), r, auth.UserID, auth.TenantID, auth.SessionID); err != nil {
		httpx.WriteError(w, r, http.StatusInternalServerError, httpx.ErrCodeInternal, "logout failed")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// SwitchTenant handles POST /api/v1/auth/switch-tenant.
func (h *Handler) SwitchTenant(w http.ResponseWriter, r *http.Request) {
	auth := middleware.MustAuthContext(r.Context())
	var in SwitchTenantInput
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteDecodeError(w, r, err)
		return
	}
	if err := validate.Get().Struct(&in); err != nil {
		httpx.WriteValidationError(w, r, err)
		return
	}

	pair, err := h.svc.SwitchTenant(r.Context(), r, auth.UserID, auth.TenantID, &in)
	if err != nil {
		switch err {
		case ErrTenantSuspended:
			httpx.WriteError(w, r, http.StatusForbidden, httpx.ErrCodeTenantSuspended, "target tenant is suspended")
		default:
			httpx.WriteError(w, r, http.StatusUnauthorized, httpx.ErrCodeInvalidCredentials, "not a member of that tenant")
		}
		return
	}
	httpx.WriteJSON(w, http.StatusOK, httpx.DataResponse[*TokenPair]{Data: pair})
}

// Me handles GET /api/v1/auth/me.
func (h *Handler) Me(w http.ResponseWriter, r *http.Request) {
	auth := middleware.MustAuthContext(r.Context())
	perms, _ := h.resolver.Get(r.Context(), auth.TenantID, auth.UserID)
	me, err := h.svc.Me(r.Context(), auth.UserID, auth.TenantID, perms)
	if err != nil {
		httpx.WriteError(w, r, http.StatusUnauthorized, httpx.ErrCodeUnauthenticated, "user not found")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, httpx.DataResponse[*MeResponse]{Data: me})
}
