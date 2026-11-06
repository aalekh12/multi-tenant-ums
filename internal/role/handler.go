package role

import (
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/yourusername/usermgmt/internal/middleware"
	"github.com/yourusername/usermgmt/internal/platform/httpx"
	"github.com/yourusername/usermgmt/internal/platform/validate"
)

// Handler handles HTTP requests for roles.
type Handler struct {
	svc *Service
}

// NewHandler creates a new role Handler.
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

// CreateRole handles POST /api/v1/roles.
func (h *Handler) CreateRole(w http.ResponseWriter, r *http.Request) {
	auth := middleware.MustAuthContext(r.Context())
	var in CreateRoleInput
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteDecodeError(w, r, err)
		return
	}
	if err := validate.Get().Struct(&in); err != nil {
		httpx.WriteValidationError(w, r, err)
		return
	}

	ro, err := h.svc.Create(r.Context(), r, auth.TenantID, auth.UserID, &in)
	if err != nil {
		switch err {
		case ErrRoleNameConflict:
			httpx.WriteError(w, r, http.StatusConflict, httpx.ErrCodeConflict, "role with this name already exists in tenant")
		default:
			httpx.WriteError(w, r, http.StatusInternalServerError, httpx.ErrCodeInternal, "failed to create role")
		}
		return
	}

	w.Header().Set("Location", "/api/v1/roles/"+ro.ID)
	httpx.WriteJSON(w, http.StatusCreated, httpx.DataResponse[*Role]{Data: ro})
}

// GetRole handles GET /api/v1/roles/{id}.
func (h *Handler) GetRole(w http.ResponseWriter, r *http.Request) {
	auth := middleware.MustAuthContext(r.Context())
	id := chi.URLParam(r, "id")
	if !isValidUUID(id) {
		httpx.WriteError(w, r, http.StatusNotFound, httpx.ErrCodeNotFound, "role not found")
		return
	}

	ro, err := h.svc.GetByID(r.Context(), auth.TenantID, id)
	if err != nil {
		if err == ErrRoleNotFound {
			httpx.WriteError(w, r, http.StatusNotFound, httpx.ErrCodeNotFound, "role not found")
			return
		}
		httpx.WriteError(w, r, http.StatusInternalServerError, httpx.ErrCodeInternal, "failed to get role")
		return
	}

	httpx.WriteJSON(w, http.StatusOK, httpx.DataResponse[*RoleWithPermissions]{Data: ro})
}

// ListRoles handles GET /api/v1/roles.
func (h *Handler) ListRoles(w http.ResponseWriter, r *http.Request) {
	auth := middleware.MustAuthContext(r.Context())
	q := r.URL.Query()
	p := httpx.ParsePagination(r)

	filter := ListFilter{
		TenantID: auth.TenantID,
		Q:        q.Get("q"),
	}

	roles, total, err := h.svc.List(r.Context(), filter, p.Page, p.PageSize)
	if err != nil {
		httpx.WriteError(w, r, http.StatusInternalServerError, httpx.ErrCodeInternal, "failed to list roles")
		return
	}
	if roles == nil {
		roles = []Role{}
	}

	httpx.WriteJSON(w, http.StatusOK, httpx.ListResponse[Role]{
		Data:       roles,
		Pagination: httpx.NewPaginationMeta(p, total),
	})
}

// UpdateRole handles PATCH /api/v1/roles/{id}.
func (h *Handler) UpdateRole(w http.ResponseWriter, r *http.Request) {
	auth := middleware.MustAuthContext(r.Context())
	id := chi.URLParam(r, "id")
	if !isValidUUID(id) {
		httpx.WriteError(w, r, http.StatusNotFound, httpx.ErrCodeNotFound, "role not found")
		return
	}

	var in UpdateRoleInput
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteDecodeError(w, r, err)
		return
	}
	if err := validate.Get().Struct(&in); err != nil {
		httpx.WriteValidationError(w, r, err)
		return
	}

	ro, err := h.svc.Update(r.Context(), r, auth.TenantID, id, auth.UserID, &in)
	if err != nil {
		switch err {
		case ErrRoleNotFound:
			httpx.WriteError(w, r, http.StatusNotFound, httpx.ErrCodeNotFound, "role not found")
		case ErrSystemRoleImmutable:
			httpx.WriteError(w, r, http.StatusConflict, httpx.ErrCodeSystemRoleImmutable, "system roles cannot be modified")
		case ErrRoleNameConflict:
			httpx.WriteError(w, r, http.StatusConflict, httpx.ErrCodeConflict, "role with this name already exists in tenant")
		default:
			httpx.WriteError(w, r, http.StatusInternalServerError, httpx.ErrCodeInternal, "failed to update role")
		}
		return
	}

	httpx.WriteJSON(w, http.StatusOK, httpx.DataResponse[*Role]{Data: ro})
}

// DeleteRole handles DELETE /api/v1/roles/{id}.
func (h *Handler) DeleteRole(w http.ResponseWriter, r *http.Request) {
	auth := middleware.MustAuthContext(r.Context())
	id := chi.URLParam(r, "id")
	if !isValidUUID(id) {
		httpx.WriteError(w, r, http.StatusNotFound, httpx.ErrCodeNotFound, "role not found")
		return
	}

	if err := h.svc.Delete(r.Context(), r, auth.TenantID, id, auth.UserID); err != nil {
		switch err {
		case ErrRoleNotFound:
			httpx.WriteError(w, r, http.StatusNotFound, httpx.ErrCodeNotFound, "role not found")
		case ErrSystemRoleImmutable:
			httpx.WriteError(w, r, http.StatusConflict, httpx.ErrCodeSystemRoleImmutable, "system roles cannot be deleted")
		default:
			httpx.WriteError(w, r, http.StatusInternalServerError, httpx.ErrCodeInternal, "failed to delete role")
		}
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// AssignPermissions handles PUT /api/v1/roles/{id}/permissions.
func (h *Handler) AssignPermissions(w http.ResponseWriter, r *http.Request) {
	auth := middleware.MustAuthContext(r.Context())
	id := chi.URLParam(r, "id")
	if !isValidUUID(id) {
		httpx.WriteError(w, r, http.StatusNotFound, httpx.ErrCodeNotFound, "role not found")
		return
	}

	var in AssignPermissionsInput
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteDecodeError(w, r, err)
		return
	}
	if err := validate.Get().Struct(&in); err != nil {
		httpx.WriteValidationError(w, r, err)
		return
	}

	if err := h.svc.AssignPermissions(r.Context(), r, auth.TenantID, id, auth.UserID, &in); err != nil {
		switch err {
		case ErrRoleNotFound:
			httpx.WriteError(w, r, http.StatusNotFound, httpx.ErrCodeNotFound, "role not found")
		case ErrSystemRoleImmutable:
			httpx.WriteError(w, r, http.StatusConflict, httpx.ErrCodeSystemRoleImmutable, "system role permissions cannot be modified")
		case ErrPrivilegeEscalation:
			httpx.WriteError(w, r, http.StatusForbidden, httpx.ErrCodeForbidden, "cannot grant permissions that you do not hold")
		default:
			httpx.WriteError(w, r, http.StatusInternalServerError, httpx.ErrCodeInternal, "failed to assign permissions")
		}
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

