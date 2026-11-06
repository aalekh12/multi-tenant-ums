// Package auth provides authentication (login, refresh, logout, switch-tenant, me).
package auth

import "time"

// LoginInput is the request body for POST /auth/login.
type LoginInput struct {
	Email      string `json:"email"       validate:"required,email"`
	Password   string `json:"password"    validate:"required"`
	TenantCode string `json:"tenant_code" validate:"required"`
}

// RefreshInput is the request body for POST /auth/refresh.
type RefreshInput struct {
	RefreshToken string `json:"refresh_token" validate:"required"`
}

// SwitchTenantInput is the request body for POST /auth/switch-tenant.
type SwitchTenantInput struct {
	TenantCode string `json:"tenant_code" validate:"required"`
}

// ChangePasswordInput is the body for PUT /users/{id}/password.
type ChangePasswordInput struct {
	OldPassword string `json:"old_password" validate:"required"`
	NewPassword string `json:"new_password" validate:"required,password_policy"`
}

// TokenPair is the access + refresh token pair returned on login/refresh.
type TokenPair struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int    `json:"expires_in"` // seconds until access token expires
}

// MeResponse is the response for GET /auth/me.
type MeResponse struct {
	User        UserInfo   `json:"user"`
	Tenant      TenantInfo `json:"tenant"`
	Roles       []RoleInfo `json:"roles"`
	Permissions []string   `json:"permissions"`
}

// UserInfo is the user sub-object in MeResponse.
type UserInfo struct {
	ID        string    `json:"id"`
	Email     string    `json:"email"`
	FullName  string    `json:"full_name"`
	CreatedAt time.Time `json:"created_at"`
}

// TenantInfo is the tenant sub-object in MeResponse.
type TenantInfo struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Code string `json:"code"`
}

// RoleInfo is a role sub-object.
type RoleInfo struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// RefreshToken is the DB record for a stored refresh token.
type RefreshToken struct {
	JTI       string
	FamilyID  string
	UserID    string
	TenantID  string
	ExpiresAt time.Time
	UsedAt    *time.Time
	RevokedAt *time.Time
	IP        *string
	UserAgent *string
}
