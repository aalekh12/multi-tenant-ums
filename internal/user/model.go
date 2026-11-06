// Package user provides user management (CRUD) scoped to a tenant via tenant_users.
package user

import "time"

// User is the user resource as returned by the API.
type User struct {
	ID        string    `json:"id"`
	Email     string    `json:"email"`
	FullName  string    `json:"full_name"`
	Status    string    `json:"status"` // active | inactive (membership status)
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// UserWithRoles extends User with roles in this tenant.
type UserWithRoles struct {
	User
	Roles []RoleRef `json:"roles"`
}

// RoleRef is a minimal role reference.
type RoleRef struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// CreateUserInput is the request body for POST /users.
type CreateUserInput struct {
	Email    string   `json:"email"     validate:"required,email"`
	FullName string   `json:"full_name" validate:"required,min=1,max=120"`
	Password string   `json:"password"  validate:"required,password_policy"`
	RoleIDs  []string `json:"role_ids"`
}

// UpdateUserInput is the request body for PATCH /users/{id}.
type UpdateUserInput struct {
	FullName *string `json:"full_name"`
	Status   *string `json:"status" validate:"omitempty,oneof=active inactive"`
}

// ChangePasswordInput is the request body for PUT /users/{id}/password.
type ChangePasswordInput struct {
	OldPassword string `json:"old_password" validate:"required"`
	NewPassword string `json:"new_password" validate:"required,password_policy"`
}

// ListFilter holds filters for listing users.
type ListFilter struct {
	TenantID       string
	Status         string
	Q              string
	RoleID         string
	IncludeDeleted bool
	Sort           string
	Order          string
}
