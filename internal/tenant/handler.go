package tenant

import (
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/yourusername/usermgmt/internal/middleware"
	"github.com/yourusername/usermgmt/internal/platform/httpx"
	"github.com/yourusername/usermgmt/internal/platform/validate"
)

// Handler handles HTTP requests for tenant resources.
type Handler struct {
	svc *Service
}

// NewHandler creates a new tenant Handler.
func NewHandler(svc *Service) *Handler {
	return &Handler{svc: svc}
}

func isValidUUID(s string) bool {
	if len(s) != 36 {
		return false
	}
	parts := strings.Split(s, "-")
	return len(parts) == 5
}

// PlatformOnlyGuard middleware checks that the caller's tenant is the platform tenant.
func (h *Handler) PlatformOnlyGuard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth, ok := middleware.AuthContextFromCtx(r.Context())
		if !ok {
			w.Header().Set("WWW-Authenticate", "Bearer")
			httpx.WriteError(w, r, http.StatusUnauthorized, httpx.ErrCodeUnauthenticated, "authentication required")
			return
		}

		isPlatform, err := h.svc.IsPlatformTenant(r.Context(), auth.TenantID)
		if err != nil || !isPlatform {
			httpx.WriteError(w, r, http.StatusForbidden, httpx.ErrCodeForbidden, "platform tenant access required")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// CreateTenant handles POST /api/v1/tenants (platform only).
func (h *Handler) CreateTenant(w http.ResponseWriter, r *http.Request) {
	auth := middleware.MustAuthContext(r.Context())
	var in CreateTenantInput
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteDecodeError(w, r, err)
		return
	}
	if err := validate.Get().Struct(&in); err != nil {
		httpx.WriteValidationError(w, r, err)
		return
	}

	t, err := h.svc.Create(r.Context(), r, auth.UserID, &in, false)
	if err != nil {
		switch err {
		case ErrCodeConflict:
			httpx.WriteError(w, r, http.StatusConflict, httpx.ErrCodeConflict, "tenant code already in use")
		default:
			httpx.WriteError(w, r, http.StatusBadRequest, httpx.ErrCodeValidationFailed, err.Error())
		}
		return
	}

	w.Header().Set("Location", "/api/v1/tenants/"+t.ID)
	httpx.WriteJSON(w, http.StatusCreated, httpx.DataResponse[*Tenant]{Data: t})
}

// ListTenants handles GET /api/v1/tenants (platform only).
func (h *Handler) ListTenants(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	p := httpx.ParsePagination(r)

	filter := ListFilter{
		Status: q.Get("status"),
		Q:      q.Get("q"),
	}

	tenants, total, err := h.svc.List(r.Context(), filter, p.Page, p.PageSize)
	if err != nil {
		httpx.WriteError(w, r, http.StatusInternalServerError, httpx.ErrCodeInternal, "failed to list tenants")
		return
	}
	if tenants == nil {
		tenants = []Tenant{}
	}

	httpx.WriteJSON(w, http.StatusOK, httpx.ListResponse[Tenant]{
		Data:       tenants,
		Pagination: httpx.NewPaginationMeta(p, total),
	})
}

// GetTenant handles GET /api/v1/tenants/{id} (platform only).
func (h *Handler) GetTenant(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if !isValidUUID(id) {
		httpx.WriteError(w, r, http.StatusNotFound, httpx.ErrCodeNotFound, "tenant not found")
		return
	}

	t, err := h.svc.GetByID(r.Context(), id)
	if err != nil {
		if err == ErrNotFound {
			httpx.WriteError(w, r, http.StatusNotFound, httpx.ErrCodeNotFound, "tenant not found")
			return
		}
		httpx.WriteError(w, r, http.StatusInternalServerError, httpx.ErrCodeInternal, "failed to get tenant")
		return
	}

	httpx.WriteJSON(w, http.StatusOK, httpx.DataResponse[*Tenant]{Data: t})
}

// UpdateTenant handles PATCH /api/v1/tenants/{id} (platform only).
func (h *Handler) UpdateTenant(w http.ResponseWriter, r *http.Request) {
	auth := middleware.MustAuthContext(r.Context())
	id := chi.URLParam(r, "id")
	if !isValidUUID(id) {
		httpx.WriteError(w, r, http.StatusNotFound, httpx.ErrCodeNotFound, "tenant not found")
		return
	}

	var in UpdateTenantInput
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteDecodeError(w, r, err)
		return
	}
	if err := validate.Get().Struct(&in); err != nil {
		httpx.WriteValidationError(w, r, err)
		return
	}

	t, err := h.svc.UpdateName(r.Context(), r, id, auth.UserID, in.Name)
	if err != nil {
		if err == ErrNotFound {
			httpx.WriteError(w, r, http.StatusNotFound, httpx.ErrCodeNotFound, "tenant not found")
			return
		}
		httpx.WriteError(w, r, http.StatusInternalServerError, httpx.ErrCodeInternal, "failed to update tenant")
		return
	}

	httpx.WriteJSON(w, http.StatusOK, httpx.DataResponse[*Tenant]{Data: t})
}

// SuspendTenant handles POST /api/v1/tenants/{id}/suspend (platform only).
func (h *Handler) SuspendTenant(w http.ResponseWriter, r *http.Request) {
	auth := middleware.MustAuthContext(r.Context())
	id := chi.URLParam(r, "id")
	if !isValidUUID(id) {
		httpx.WriteError(w, r, http.StatusNotFound, httpx.ErrCodeNotFound, "tenant not found")
		return
	}

	t, err := h.svc.Suspend(r.Context(), r, id, auth.UserID)
	if err != nil {
		switch err {
		case ErrCannotSuspendPlatform:
			httpx.WriteError(w, r, http.StatusConflict, httpx.ErrCodeConflict, "cannot suspend the platform tenant")
		case ErrNotFound:
			httpx.WriteError(w, r, http.StatusNotFound, httpx.ErrCodeNotFound, "tenant not found")
		default:
			httpx.WriteError(w, r, http.StatusInternalServerError, httpx.ErrCodeInternal, "failed to suspend tenant")
		}
		return
	}

	httpx.WriteJSON(w, http.StatusOK, httpx.DataResponse[*Tenant]{Data: t})
}

// ActivateTenant handles POST /api/v1/tenants/{id}/activate (platform only).
func (h *Handler) ActivateTenant(w http.ResponseWriter, r *http.Request) {
	auth := middleware.MustAuthContext(r.Context())
	id := chi.URLParam(r, "id")
	if !isValidUUID(id) {
		httpx.WriteError(w, r, http.StatusNotFound, httpx.ErrCodeNotFound, "tenant not found")
		return
	}

	t, err := h.svc.Activate(r.Context(), r, id, auth.UserID)
	if err != nil {
		if err == ErrNotFound {
			httpx.WriteError(w, r, http.StatusNotFound, httpx.ErrCodeNotFound, "tenant not found")
			return
		}
		httpx.WriteError(w, r, http.StatusInternalServerError, httpx.ErrCodeInternal, "failed to activate tenant")
		return
	}

	httpx.WriteJSON(w, http.StatusOK, httpx.DataResponse[*Tenant]{Data: t})
}

// GetCurrentTenant handles GET /api/v1/tenant.
func (h *Handler) GetCurrentTenant(w http.ResponseWriter, r *http.Request) {
	auth := middleware.MustAuthContext(r.Context())
	t, err := h.svc.GetByID(r.Context(), auth.TenantID)
	if err != nil {
		if err == ErrNotFound {
			httpx.WriteError(w, r, http.StatusNotFound, httpx.ErrCodeNotFound, "tenant not found")
			return
		}
		httpx.WriteError(w, r, http.StatusInternalServerError, httpx.ErrCodeInternal, "failed to get current tenant")
		return
	}

	httpx.WriteJSON(w, http.StatusOK, httpx.DataResponse[*Tenant]{Data: t})
}

// UpdateCurrentTenant handles PATCH /api/v1/tenant.
func (h *Handler) UpdateCurrentTenant(w http.ResponseWriter, r *http.Request) {
	auth := middleware.MustAuthContext(r.Context())
	var in UpdateTenantInput
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteDecodeError(w, r, err)
		return
	}
	if err := validate.Get().Struct(&in); err != nil {
		httpx.WriteValidationError(w, r, err)
		return
	}

	t, err := h.svc.UpdateName(r.Context(), r, auth.TenantID, auth.UserID, in.Name)
	if err != nil {
		if err == ErrNotFound {
			httpx.WriteError(w, r, http.StatusNotFound, httpx.ErrCodeNotFound, "tenant not found")
			return
		}
		httpx.WriteError(w, r, http.StatusInternalServerError, httpx.ErrCodeInternal, "failed to update current tenant")
		return
	}

	httpx.WriteJSON(w, http.StatusOK, httpx.DataResponse[*Tenant]{Data: t})
}

