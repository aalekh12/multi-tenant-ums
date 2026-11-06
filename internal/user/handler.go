package user

import (
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/multi_tenante_ums/internal/middleware"
	"github.com/multi_tenante_ums/internal/platform/httpx"
	"github.com/multi_tenante_ums/internal/platform/validate"
)

// Handler is the HTTP handler for user routes.
type Handler struct {
	svc *Service
}

// NewHandler creates a new user Handler.
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

// CreateUser handles POST /api/v1/users.
func (h *Handler) CreateUser(w http.ResponseWriter, r *http.Request) {
	auth := middleware.MustAuthContext(r.Context())
	var in CreateUserInput
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteDecodeError(w, r, err)
		return
	}
	if err := validate.Get().Struct(&in); err != nil {
		httpx.WriteValidationError(w, r, err)
		return
	}

	u, err := h.svc.Create(r.Context(), r, auth.TenantID, auth.UserID, &in)
	if err != nil {
		switch err {
		case ErrEmailConflict:
			httpx.WriteError(w, r, http.StatusConflict, httpx.ErrCodeEmailAlreadyExists, "user is already a member of this tenant")
		case ErrRoleNotFound:
			httpx.WriteError(w, r, http.StatusNotFound, httpx.ErrCodeRoleNotFound, "one or more roles not found in this tenant")
		default:
			httpx.WriteError(w, r, http.StatusInternalServerError, httpx.ErrCodeInternal, "failed to create user")
		}
		return
	}
	w.Header().Set("Location", "/api/v1/users/"+u.ID)
	httpx.WriteJSON(w, http.StatusCreated, httpx.DataResponse[*UserWithRoles]{Data: u})
}

// GetUser handles GET /api/v1/users/{id}.
func (h *Handler) GetUser(w http.ResponseWriter, r *http.Request) {
	auth := middleware.MustAuthContext(r.Context())
	id := chi.URLParam(r, "id")
	if !isValidUUID(id) {
		httpx.WriteError(w, r, http.StatusNotFound, httpx.ErrCodeNotFound, "user not found")
		return
	}

	u, err := h.svc.GetByID(r.Context(), auth.TenantID, id)
	if err != nil {
		if err == ErrNotFound {
			httpx.WriteError(w, r, http.StatusNotFound, httpx.ErrCodeNotFound, "user not found")
			return
		}
		httpx.WriteError(w, r, http.StatusInternalServerError, httpx.ErrCodeInternal, "failed to get user")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, httpx.DataResponse[*UserWithRoles]{Data: u})
}

// ListUsers handles GET /api/v1/users.
func (h *Handler) ListUsers(w http.ResponseWriter, r *http.Request) {
	auth := middleware.MustAuthContext(r.Context())
	q := r.URL.Query()
	p := httpx.ParsePagination(r)

	includeDeleted := q.Get("include_deleted") == "true"
	filter := ListFilter{
		TenantID:       auth.TenantID,
		Status:         q.Get("status"),
		Q:              q.Get("q"),
		RoleID:         q.Get("role_id"),
		IncludeDeleted: includeDeleted,
		Sort:           q.Get("sort"),
		Order:          q.Get("order"),
	}

	users, total, err := h.svc.List(r.Context(), filter, p.Page, p.PageSize)
	if err != nil {
		httpx.WriteError(w, r, http.StatusInternalServerError, httpx.ErrCodeInternal, "failed to list users")
		return
	}
	if users == nil {
		users = []User{}
	}
	httpx.WriteJSON(w, http.StatusOK, httpx.ListResponse[User]{
		Data:       users,
		Pagination: httpx.NewPaginationMeta(p, total),
	})
}

// UpdateUser handles PATCH /api/v1/users/{id}.
func (h *Handler) UpdateUser(w http.ResponseWriter, r *http.Request) {
	auth := middleware.MustAuthContext(r.Context())
	id := chi.URLParam(r, "id")
	if !isValidUUID(id) {
		httpx.WriteError(w, r, http.StatusNotFound, httpx.ErrCodeNotFound, "user not found")
		return
	}

	var in UpdateUserInput
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteDecodeError(w, r, err)
		return
	}
	if err := validate.Get().Struct(&in); err != nil {
		httpx.WriteValidationError(w, r, err)
		return
	}

	u, err := h.svc.Update(r.Context(), r, auth.TenantID, id, auth.UserID, &in)
	if err != nil {
		if err == ErrNotFound {
			httpx.WriteError(w, r, http.StatusNotFound, httpx.ErrCodeNotFound, "user not found")
			return
		}
		httpx.WriteError(w, r, http.StatusInternalServerError, httpx.ErrCodeInternal, "failed to update user")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, httpx.DataResponse[*User]{Data: u})
}

// DeleteUser handles DELETE /api/v1/users/{id}.
func (h *Handler) DeleteUser(w http.ResponseWriter, r *http.Request) {
	auth := middleware.MustAuthContext(r.Context())
	id := chi.URLParam(r, "id")
	if !isValidUUID(id) {
		httpx.WriteError(w, r, http.StatusNotFound, httpx.ErrCodeNotFound, "user not found")
		return
	}

	if err := h.svc.Delete(r.Context(), r, auth.TenantID, id, auth.UserID); err != nil {
		switch err {
		case ErrSelfDelete:
			httpx.WriteError(w, r, http.StatusConflict, httpx.ErrCodeSelfDelete, "cannot delete yourself")
		case ErrNotFound:
			httpx.WriteError(w, r, http.StatusNotFound, httpx.ErrCodeNotFound, "user not found")
		default:
			httpx.WriteError(w, r, http.StatusInternalServerError, httpx.ErrCodeInternal, "failed to delete user")
		}
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ChangePassword handles PUT /api/v1/users/{id}/password.
func (h *Handler) ChangePassword(w http.ResponseWriter, r *http.Request) {
	auth := middleware.MustAuthContext(r.Context())
	id := chi.URLParam(r, "id")
	if !isValidUUID(id) {
		httpx.WriteError(w, r, http.StatusNotFound, httpx.ErrCodeNotFound, "user not found")
		return
	}

	var in ChangePasswordInput
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteDecodeError(w, r, err)
		return
	}
	if err := validate.Get().Struct(&in); err != nil {
		httpx.WriteValidationError(w, r, err)
		return
	}

	if err := h.svc.ChangePassword(r.Context(), r, auth.TenantID, id, auth.UserID, &in); err != nil {
		if err == ErrNotFound {
			httpx.WriteError(w, r, http.StatusNotFound, httpx.ErrCodeNotFound, "user not found")
			return
		}
		httpx.WriteError(w, r, http.StatusBadRequest, httpx.ErrCodeValidationFailed, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// AssignRoles handles PUT /api/v1/users/{id}/roles.
func (h *Handler) AssignRoles(w http.ResponseWriter, r *http.Request) {
	auth := middleware.MustAuthContext(r.Context())
	id := chi.URLParam(r, "id")
	if !isValidUUID(id) {
		httpx.WriteError(w, r, http.StatusNotFound, httpx.ErrCodeNotFound, "user not found")
		return
	}

	var in struct {
		RoleIDs []string `json:"role_ids"`
	}
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteDecodeError(w, r, err)
		return
	}

	// Validate role IDs belong to this tenant
	if err := h.svc.AssignRoles(r.Context(), r, auth.TenantID, id, auth.UserID, in.RoleIDs); err != nil {
		switch err {
		case ErrRoleNotFound:
			httpx.WriteError(w, r, http.StatusNotFound, httpx.ErrCodeRoleNotFound, "role not found in this tenant")
		case ErrNotFound:
			httpx.WriteError(w, r, http.StatusNotFound, httpx.ErrCodeNotFound, "user not found")
		default:
			httpx.WriteError(w, r, http.StatusInternalServerError, httpx.ErrCodeInternal, "failed to assign roles")
		}
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// AddRole handles POST /api/v1/users/{id}/roles/{roleId}.
func (h *Handler) AddRole(w http.ResponseWriter, r *http.Request) {
	auth := middleware.MustAuthContext(r.Context())
	id := chi.URLParam(r, "id")
	roleID := chi.URLParam(r, "roleId")
	if !isValidUUID(id) || !isValidUUID(roleID) {
		httpx.WriteError(w, r, http.StatusNotFound, httpx.ErrCodeNotFound, "resource not found")
		return
	}

	if err := h.svc.AddRole(r.Context(), r, auth.TenantID, id, roleID, auth.UserID); err != nil {
		switch err {
		case ErrRoleNotFound:
			httpx.WriteError(w, r, http.StatusNotFound, httpx.ErrCodeRoleNotFound, "role not found in this tenant")
		case ErrNotFound:
			httpx.WriteError(w, r, http.StatusNotFound, httpx.ErrCodeNotFound, "user not found")
		default:
			httpx.WriteError(w, r, http.StatusInternalServerError, httpx.ErrCodeInternal, "failed to add role")
		}
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// RemoveRole handles DELETE /api/v1/users/{id}/roles/{roleId}.
func (h *Handler) RemoveRole(w http.ResponseWriter, r *http.Request) {
	auth := middleware.MustAuthContext(r.Context())
	id := chi.URLParam(r, "id")
	roleID := chi.URLParam(r, "roleId")
	if !isValidUUID(id) || !isValidUUID(roleID) {
		httpx.WriteError(w, r, http.StatusNotFound, httpx.ErrCodeNotFound, "resource not found")
		return
	}

	if err := h.svc.RemoveRole(r.Context(), r, auth.TenantID, id, roleID, auth.UserID); err != nil {
		switch err {
		case ErrRoleNotFound:
			httpx.WriteError(w, r, http.StatusNotFound, httpx.ErrCodeRoleNotFound, "role not found in this tenant")
		case ErrNotFound:
			httpx.WriteError(w, r, http.StatusNotFound, httpx.ErrCodeNotFound, "user not found")
		default:
			httpx.WriteError(w, r, http.StatusInternalServerError, httpx.ErrCodeInternal, "failed to remove role")
		}
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
