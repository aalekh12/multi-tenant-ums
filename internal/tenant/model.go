// Package tenant provides tenant management (CRUD, suspend, activate).
package tenant

import (
	"context"
	"time"
)

// Tenant represents a tenant record.
type Tenant struct {
	ID         string    `json:"id"`
	Name       string    `json:"name"`
	Code       string    `json:"code"`
	Status     string    `json:"status"`
	IsPlatform bool      `json:"is_platform"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
}

// CreateTenantInput is the input for creating a new tenant.
type CreateTenantInput struct {
	Name  string    `json:"name"  validate:"required,min=2,max=120"`
	Code  string    `json:"code"  validate:"required,min=2,max=63"`
	Admin AdminInput `json:"admin" validate:"required"`
}

// AdminInput describes the initial admin user for a new tenant.
type AdminInput struct {
	Email    string `json:"email"     validate:"required,email"`
	FullName string `json:"full_name" validate:"required,min=1,max=120"`
	Password string `json:"password"  validate:"required,password_policy"`
}

// UpdateTenantInput is the input for updating a tenant (name only).
type UpdateTenantInput struct {
	Name string `json:"name" validate:"required,min=2,max=120"`
}

// ListFilter holds filters for listing tenants.
type ListFilter struct {
	Status string
	Q      string
}

// Repository is the interface for tenant data access.
type Repository interface {
	Create(ctx context.Context, t *Tenant) error
	GetByID(ctx context.Context, id string) (*Tenant, error)
	GetByCode(ctx context.Context, code string) (*Tenant, error)
	GetPlatformTenant(ctx context.Context) (*Tenant, error)
	List(ctx context.Context, f ListFilter, page, pageSize int) ([]Tenant, int64, error)
	Update(ctx context.Context, id, name string) (*Tenant, error)
	SetStatus(ctx context.Context, id, status string) (*Tenant, error)
	IsPlatformTenant(ctx context.Context, id string) (bool, error)
}

