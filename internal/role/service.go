package role

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/yourusername/usermgmt/internal/audit"
	"github.com/yourusername/usermgmt/internal/permission"
)

// Common errors.
var (
	ErrRoleNotFound        = errors.New("role not found")
	ErrSystemRoleImmutable = errors.New("system roles are immutable")
	ErrPrivilegeEscalation = errors.New("cannot grant permissions you do not hold")
	ErrRoleNameConflict    = errors.New("role name already exists in this tenant")
)

// Repository is the interface for role data operations.
type Repository interface {
	Create(ctx context.Context, tenantID, name, description string) (*Role, error)
	GetByID(ctx context.Context, tenantID, roleID string) (*Role, error)
	GetPermissions(ctx context.Context, tenantID, roleID string) ([]PermissionRef, error)
	List(ctx context.Context, f ListFilter, page, pageSize int) ([]Role, int64, error)
	Update(ctx context.Context, tx pgx.Tx, tenantID, roleID string, name, description *string) (*Role, error)
	Delete(ctx context.Context, tx pgx.Tx, tenantID, roleID string) error
	ReplacePermissions(ctx context.Context, tx pgx.Tx, tenantID, roleID string, permCodes []string) error
	GetUserIDsWithRole(ctx context.Context, tenantID, roleID string) ([]string, error)
}

// DB is the database interface for transactions.
type DB interface {
	Begin(ctx context.Context) (pgx.Tx, error)
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
}

// Service holds role business logic.
type Service struct {
	db       DB
	repo     Repository
	resolver *permission.Resolver
	auditor  *audit.Recorder
}

// NewService creates a new role Service.
func NewService(db DB, repo Repository, resolver *permission.Resolver, auditor *audit.Recorder) *Service {
	return &Service{db: db, repo: repo, resolver: resolver, auditor: auditor}
}

// Create creates a new custom role in a tenant.
func (s *Service) Create(ctx context.Context, r *http.Request, tenantID, actorID string, in *CreateRoleInput) (*Role, error) {
	ro, err := s.repo.Create(ctx, tenantID, in.Name, in.Description)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return nil, ErrRoleNameConflict
		}
		return nil, fmt.Errorf("create role: %w", err)
	}

	ip, ua, reqID := audit.EventFromRequest(r)
	_ = s.auditor.Record(ctx, s.db, audit.Event{
		TenantID:    &tenantID,
		ActorUserID: &actorID,
		Action:      "role.create",
		TargetType:  "role",
		TargetID:    &ro.ID,
		Metadata:    map[string]any{"name": ro.Name},
		Success:     true,
		IP:          ip,
		UserAgent:   ua,
		RequestID:   reqID,
	})

	return ro, nil
}

// GetByID retrieves a role and its assigned permissions within a tenant.
func (s *Service) GetByID(ctx context.Context, tenantID, roleID string) (*RoleWithPermissions, error) {
	ro, err := s.repo.GetByID(ctx, tenantID, roleID)
	if err != nil {
		return nil, err
	}
	if ro == nil {
		return nil, ErrRoleNotFound
	}

	perms, err := s.repo.GetPermissions(ctx, tenantID, roleID)
	if err != nil {
		return nil, fmt.Errorf("get role permissions: %w", err)
	}
	if perms == nil {
		perms = []PermissionRef{}
	}

	return &RoleWithPermissions{Role: *ro, Permissions: perms}, nil
}

// List lists roles in a tenant.
func (s *Service) List(ctx context.Context, f ListFilter, page, pageSize int) ([]Role, int64, error) {
	return s.repo.List(ctx, f, page, pageSize)
}

// Update updates a role's name and description. Enforces system role immutability.
func (s *Service) Update(ctx context.Context, r *http.Request, tenantID, roleID, actorID string, in *UpdateRoleInput) (*Role, error) {
	ro, err := s.repo.GetByID(ctx, tenantID, roleID)
	if err != nil {
		return nil, err
	}
	if ro == nil {
		return nil, ErrRoleNotFound
	}
	if ro.IsSystem {
		return nil, ErrSystemRoleImmutable
	}

	tx, err := s.db.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	updated, err := s.repo.Update(ctx, tx, tenantID, roleID, in.Name, in.Description)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return nil, ErrRoleNameConflict
		}
		return nil, err
	}

	ip, ua, reqID := audit.EventFromRequest(r)
	_ = s.auditor.Record(ctx, tx, audit.Event{
		TenantID:    &tenantID,
		ActorUserID: &actorID,
		Action:      "role.update",
		TargetType:  "role",
		TargetID:    &roleID,
		Metadata:    map[string]any{"name": in.Name, "description": in.Description},
		Success:     true,
		IP:          ip,
		UserAgent:   ua,
		RequestID:   reqID,
	})

	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}

	return updated, nil
}

// Delete removes a role. Enforces system role immutability and invalidates cache.
func (s *Service) Delete(ctx context.Context, r *http.Request, tenantID, roleID, actorID string) error {
	ro, err := s.repo.GetByID(ctx, tenantID, roleID)
	if err != nil {
		return err
	}
	if ro == nil {
		return ErrRoleNotFound
	}
	if ro.IsSystem {
		return ErrSystemRoleImmutable
	}

	// Fetch users holding this role before delete for invalidation
	userIDs, _ := s.repo.GetUserIDsWithRole(ctx, tenantID, roleID)

	tx, err := s.db.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if err := s.repo.Delete(ctx, tx, tenantID, roleID); err != nil {
		return err
	}

	ip, ua, reqID := audit.EventFromRequest(r)
	_ = s.auditor.Record(ctx, tx, audit.Event{
		TenantID:    &tenantID,
		ActorUserID: &actorID,
		Action:      "role.delete",
		TargetType:  "role",
		TargetID:    &roleID,
		Success:     true,
		IP:          ip,
		UserAgent:   ua,
		RequestID:   reqID,
	})

	if err := tx.Commit(ctx); err != nil {
		return err
	}

	// Invalidate permission cache for all users who had this role
	s.resolver.InvalidateUsersWithRole(ctx, tenantID, userIDs)
	s.resolver.InvalidateTenant(ctx, tenantID)
	return nil
}

// AssignPermissions replaces a role's permissions.
// Enforces:
// 1. System role immutability (cannot modify permissions of system roles)
// 2. Privilege-escalation guard (actor can only grant permissions they hold)
func (s *Service) AssignPermissions(ctx context.Context, r *http.Request, tenantID, roleID, actorID string, in *AssignPermissionsInput) error {
	ro, err := s.repo.GetByID(ctx, tenantID, roleID)
	if err != nil {
		return err
	}
	if ro == nil {
		return ErrRoleNotFound
	}
	if ro.IsSystem {
		return ErrSystemRoleImmutable
	}

	// Privilege-escalation check: actor must currently hold all requested permissions
	actorPerms, err := s.resolver.Get(ctx, tenantID, actorID)
	if err != nil {
		return fmt.Errorf("check actor permissions: %w", err)
	}

	actorPermSet := make(map[string]bool, len(actorPerms))
	for _, p := range actorPerms {
		actorPermSet[p] = true
	}

	for _, reqPerm := range in.PermissionCodes {
		if !actorPermSet[reqPerm] {
			return ErrPrivilegeEscalation
		}
	}

	userIDs, _ := s.repo.GetUserIDsWithRole(ctx, tenantID, roleID)

	tx, err := s.db.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if err := s.repo.ReplacePermissions(ctx, tx, tenantID, roleID, in.PermissionCodes); err != nil {
		return fmt.Errorf("replace permissions: %w", err)
	}

	ip, ua, reqID := audit.EventFromRequest(r)
	_ = s.auditor.Record(ctx, tx, audit.Event{
		TenantID:    &tenantID,
		ActorUserID: &actorID,
		Action:      "role.permissions_update",
		TargetType:  "role",
		TargetID:    &roleID,
		Metadata:    map[string]any{"permissions": in.PermissionCodes},
		Success:     true,
		IP:          ip,
		UserAgent:   ua,
		RequestID:   reqID,
	})

	if err := tx.Commit(ctx); err != nil {
		return err
	}

	// Explicit invalidation after commit
	s.resolver.InvalidateUsersWithRole(ctx, tenantID, userIDs)
	s.resolver.InvalidateTenant(ctx, tenantID)

	return nil
}

