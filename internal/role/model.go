// Package role provides role and permission assignment management.
package role

import "time"

// Role represents a tenant-specific role.
type Role struct {
	ID          string    `json:"id"`
	TenantID    string    `json:"tenant_id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	IsSystem    bool      `json:"is_system"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// RoleWithPermissions includes the permissions mapped to a role.
type RoleWithPermissions struct {
	Role
	Permissions []PermissionRef `json:"permissions"`
}

// PermissionRef is a minimal permission object.
type PermissionRef struct {
	ID          int16  `json:"id"`
	Code        string `json:"code"`
	Description string `json:"description"`
}

// CreateRoleInput is the input for POST /roles.
type CreateRoleInput struct {
	Name        string `json:"name"        validate:"required,min=2,max=64"`
	Description string `json:"description" validate:"max=255"`
}

// UpdateRoleInput is the input for PATCH /roles/{id}.
type UpdateRoleInput struct {
	Name        *string `json:"name"        validate:"omitempty,min=2,max=64"`
	Description *string `json:"description" validate:"omitempty,max=255"`
}

// AssignPermissionsInput is the input for PUT /roles/{id}/permissions.
type AssignPermissionsInput struct {
	PermissionCodes []string `json:"permission_codes" validate:"required"`
}

// ListFilter holds filters for listing roles.
type ListFilter struct {
	TenantID string
	Q        string
}

