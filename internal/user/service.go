package user

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/yourusername/usermgmt/internal/audit"
	"github.com/yourusername/usermgmt/internal/permission"
	"github.com/yourusername/usermgmt/internal/platform/cache"
	"github.com/yourusername/usermgmt/internal/platform/password"
)

// DB is the database interface for user transactions.
type DB interface {
	Begin(ctx context.Context) (pgx.Tx, error)
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
}

// Repository is the repository interface for user domain.
type Repository interface {
	FindByEmail(ctx context.Context, email string) (*DBUser, error)
	FindByEmailTx(ctx context.Context, tx pgx.Tx, email string) (*DBUser, error)
	GetByIDInTenant(ctx context.Context, tenantID, userID string) (*DBUser, error)
	GetMembership(ctx context.Context, tenantID, userID string) (*MembershipRow, error)
	CountActiveMemberships(ctx context.Context, tx pgx.Tx, userID string) (int, error)
	CreateUser(ctx context.Context, tx pgx.Tx, email, passwordHash, fullName string) (string, time.Time, time.Time, error)
	CreateMembership(ctx context.Context, tx pgx.Tx, tenantID, userID, status string) error
	AssignRoles(ctx context.Context, tx pgx.Tx, tenantID, userID, assignedBy string, roleIDs []string) error
	AddRole(ctx context.Context, tx pgx.Tx, tenantID, userID, roleID, assignedBy string) error
	RemoveRole(ctx context.Context, tx pgx.Tx, tenantID, userID, roleID string) error
	GetUserRoles(ctx context.Context, tenantID, userID string) ([]RoleRef, error)
	SoftDeleteMembership(ctx context.Context, tx pgx.Tx, tenantID, userID string) error
	SoftDeleteUser(ctx context.Context, tx pgx.Tx, userID string) error
	UpdateUser(ctx context.Context, tx pgx.Tx, tenantID, userID string, fullName *string, status *string) error
	UpdatePassword(ctx context.Context, tx pgx.Tx, userID, hash string) error
	RevokeUserTenantTokens(ctx context.Context, tx pgx.Tx, userID, tenantID string) error
	RoleExists(ctx context.Context, tenantID, roleID string) (bool, error)
	List(ctx context.Context, f ListFilter, page, pageSize int) ([]DBUser, int64, error)
}

// ErrNotFound is returned when a user is not found in this tenant.
var ErrNotFound = errors.New("user not found")

// ErrEmailConflict is returned when the email is already an active member.
var ErrEmailConflict = errors.New("email already exists in this tenant")

// ErrSelfDelete is returned when a user tries to delete themselves.
var ErrSelfDelete = errors.New("cannot delete yourself")

// ErrRoleNotFound is returned when a role does not belong to this tenant.
var ErrRoleNotFound = errors.New("role not found in this tenant")

// Service holds user business logic.
type Service struct {
	db       DB
	repo     Repository
	hasher   *password.Hasher
	resolver *permission.Resolver
	cache    cache.Cache
	auditor  *audit.Recorder
}

// NewService creates a new user Service.
func NewService(
	db DB,
	repo Repository,
	hasher *password.Hasher,
	resolver *permission.Resolver,
	c cache.Cache,
	auditor *audit.Recorder,
) *Service {
	return &Service{db: db, repo: repo, hasher: hasher, resolver: resolver, cache: c, auditor: auditor}
}

func toUser(u *DBUser) *User {
	return &User{
		ID:        u.ID,
		Email:     u.Email,
		FullName:  u.FullName,
		Status:    u.Status,
		CreatedAt: u.CreatedAt,
		UpdatedAt: u.UpdatedAt,
	}
}

// Create creates a new user in the given tenant.
// If the email already exists globally, adds a membership instead (Decision 3).
func (s *Service) Create(ctx context.Context, r *http.Request, tenantID, actorID string, in *CreateUserInput) (*UserWithRoles, error) {
	// Validate role IDs belong to this tenant
	for _, rid := range in.RoleIDs {
		exists, err := s.repo.RoleExists(ctx, tenantID, rid)
		if err != nil {
			return nil, fmt.Errorf("user: check role: %w", err)
		}
		if !exists {
			return nil, ErrRoleNotFound
		}
	}

	hash, err := s.hasher.Hash(in.Password)
	if err != nil {
		return nil, fmt.Errorf("user: hash password: %w", err)
	}

	tx, err := s.db.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("user: begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// Check if global user already exists
	existing, err := s.repo.FindByEmailTx(ctx, tx, in.Email)
	if err != nil {
		return nil, fmt.Errorf("user: find by email: %w", err)
	}

	var userID string
	isNew := false

	if existing != nil {
		// Check if already active member of this tenant
		mem, memErr := s.repo.GetMembership(ctx, tenantID, existing.ID)
		if memErr != nil {
			return nil, fmt.Errorf("user: get membership: %w", memErr)
		}
		if mem != nil && mem.DeletedAt == nil {
			return nil, ErrEmailConflict
		}
		userID = existing.ID
	} else {
		// Create new global user
		var id string
		id, _, _, err = s.repo.CreateUser(ctx, tx, in.Email, hash, in.FullName)
		if err != nil {
			return nil, fmt.Errorf("user: create: %w", err)
		}
		userID = id
		isNew = true
	}
	_ = isNew

	// Create/restore membership
	if err := s.repo.CreateMembership(ctx, tx, tenantID, userID, "active"); err != nil {
		return nil, fmt.Errorf("user: create membership: %w", err)
	}

	// Assign roles
	if len(in.RoleIDs) > 0 {
		if err := s.repo.AssignRoles(ctx, tx, tenantID, userID, actorID, in.RoleIDs); err != nil {
			return nil, fmt.Errorf("user: assign roles: %w", err)
		}
	}

	// Write audit
	ip, ua, reqID := audit.EventFromRequest(r)
	uid := actorID
	tid := tenantID
	_ = s.auditor.Record(ctx, tx, audit.Event{
		TenantID: &tid, ActorUserID: &uid,
		Action: "user.create", TargetType: "user", TargetID: &userID,
		Metadata:  map[string]any{"email": in.Email, "full_name": in.FullName},
		Success:   true,
		IP:        ip, UserAgent: ua, RequestID: reqID,
	})

	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("user: commit: %w", err)
	}

	// Invalidate permission cache for this user
	s.resolver.InvalidateUser(ctx, tenantID, userID)

	// Fetch the created user
	dbU, err := s.repo.GetByIDInTenant(ctx, tenantID, userID)
	if err != nil || dbU == nil {
		return nil, fmt.Errorf("user: fetch after create: %w", err)
	}
	roles, _ := s.repo.GetUserRoles(ctx, tenantID, userID)
	if roles == nil {
		roles = []RoleRef{}
	}
	return &UserWithRoles{User: *toUser(dbU), Roles: roles}, nil
}

// GetByID retrieves a user by id within a tenant (404 for cross-tenant).
func (s *Service) GetByID(ctx context.Context, tenantID, userID string) (*UserWithRoles, error) {
	dbU, err := s.repo.GetByIDInTenant(ctx, tenantID, userID)
	if err != nil {
		return nil, fmt.Errorf("user: get: %w", err)
	}
	if dbU == nil {
		return nil, ErrNotFound
	}
	roles, _ := s.repo.GetUserRoles(ctx, tenantID, userID)
	if roles == nil {
		roles = []RoleRef{}
	}
	return &UserWithRoles{User: *toUser(dbU), Roles: roles}, nil
}

// List retrieves users in a tenant with filters and pagination.
func (s *Service) List(ctx context.Context, f ListFilter, page, pageSize int) ([]User, int64, error) {
	users, total, err := s.repo.List(ctx, f, page, pageSize)
	if err != nil {
		return nil, 0, err
	}
	out := make([]User, len(users))
	for i, u := range users {
		out[i] = *toUser(&u)
	}
	return out, total, nil
}

// Update updates a user within a tenant.
func (s *Service) Update(ctx context.Context, r *http.Request, tenantID, userID, actorID string, in *UpdateUserInput) (*User, error) {
	dbU, err := s.repo.GetByIDInTenant(ctx, tenantID, userID)
	if err != nil || dbU == nil {
		return nil, ErrNotFound
	}

	tx, err := s.db.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("user: begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if err := s.repo.UpdateUser(ctx, tx, tenantID, userID, in.FullName, in.Status); err != nil {
		return nil, fmt.Errorf("user: update: %w", err)
	}

	// Write audit
	ip, ua, reqID := audit.EventFromRequest(r)
	uid := actorID
	tid := tenantID
	_ = s.auditor.Record(ctx, tx, audit.Event{
		TenantID: &tid, ActorUserID: &uid,
		Action: "user.update", TargetType: "user", TargetID: &userID,
		Metadata: map[string]any{"full_name": in.FullName, "status": in.Status},
		Success:  true,
		IP:       ip, UserAgent: ua, RequestID: reqID,
	})

	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("user: commit: %w", err)
	}

	updated, _ := s.repo.GetByIDInTenant(ctx, tenantID, userID)
	if updated == nil {
		return nil, ErrNotFound
	}
	return toUser(updated), nil
}

// Delete soft-deletes a user from the given tenant (Decision 2).
func (s *Service) Delete(ctx context.Context, r *http.Request, tenantID, userID, actorID string) error {
	if userID == actorID {
		return ErrSelfDelete
	}
	dbU, err := s.repo.GetByIDInTenant(ctx, tenantID, userID)
	if err != nil || dbU == nil {
		return ErrNotFound
	}

	tx, err := s.db.Begin(ctx)
	if err != nil {
		return fmt.Errorf("user: begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if err := s.repo.SoftDeleteMembership(ctx, tx, tenantID, userID); err != nil {
		return fmt.Errorf("user: soft delete membership: %w", err)
	}
	if err := s.repo.RevokeUserTenantTokens(ctx, tx, userID, tenantID); err != nil {
		return fmt.Errorf("user: revoke tokens: %w", err)
	}

	// If no active memberships remain, soft-delete global user record
	count, err := s.repo.CountActiveMemberships(ctx, tx, userID)
	if err != nil {
		return fmt.Errorf("user: count memberships: %w", err)
	}
	if count == 0 {
		if err := s.repo.SoftDeleteUser(ctx, tx, userID); err != nil {
			return fmt.Errorf("user: soft delete global: %w", err)
		}
	}

	ip, ua, reqID := audit.EventFromRequest(r)
	uid := actorID
	tid := tenantID
	_ = s.auditor.Record(ctx, tx, audit.Event{
		TenantID: &tid, ActorUserID: &uid,
		Action: "user.delete", TargetType: "user", TargetID: &userID,
		Metadata: map[string]any{"remaining_memberships": count},
		Success:  true,
		IP:       ip, UserAgent: ua, RequestID: reqID,
	})

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("user: commit: %w", err)
	}

	// Invalidate cache
	s.resolver.InvalidateUser(ctx, tenantID, userID)
	return nil
}

// ChangePassword updates a user's password.
func (s *Service) ChangePassword(ctx context.Context, r *http.Request, tenantID, userID, actorID string, in *ChangePasswordInput) error {
	dbU, err := s.repo.GetByIDInTenant(ctx, tenantID, userID)
	if err != nil || dbU == nil {
		return ErrNotFound
	}
	if err := s.hasher.Compare(dbU.PasswordHash, in.OldPassword); err != nil {
		return fmt.Errorf("invalid old password")
	}
	hash, err := s.hasher.Hash(in.NewPassword)
	if err != nil {
		return fmt.Errorf("user: hash: %w", err)
	}

	tx, err := s.db.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if err := s.repo.UpdatePassword(ctx, tx, userID, hash); err != nil {
		return err
	}

	ip, ua, reqID := audit.EventFromRequest(r)
	uid := actorID
	tid := tenantID
	_ = s.auditor.Record(ctx, tx, audit.Event{
		TenantID: &tid, ActorUserID: &uid,
		Action: "user.password_change", TargetType: "user", TargetID: &userID,
		Metadata: map[string]any{},
		Success:  true,
		IP:       ip, UserAgent: ua, RequestID: reqID,
	})

	return tx.Commit(ctx)
}

// AssignRoles replaces the user's roles in the tenant.
func (s *Service) AssignRoles(ctx context.Context, r *http.Request, tenantID, userID, actorID string, roleIDs []string) error {
	for _, rid := range roleIDs {
		exists, err := s.repo.RoleExists(ctx, tenantID, rid)
		if err != nil {
			return err
		}
		if !exists {
			return ErrRoleNotFound
		}
	}

	if _, err := s.GetByID(ctx, tenantID, userID); err != nil {
		return err
	}

	tx, err := s.db.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if err := s.repo.AssignRoles(ctx, tx, tenantID, userID, actorID, roleIDs); err != nil {
		return err
	}

	ip, ua, reqID := audit.EventFromRequest(r)
	uid := actorID
	tid := tenantID
	_ = s.auditor.Record(ctx, tx, audit.Event{
		TenantID:    &tid,
		ActorUserID: &uid,
		Action:      "user.roles_update",
		TargetType:  "user",
		TargetID:    &userID,
		Metadata:    map[string]any{"role_ids": roleIDs},
		Success:     true,
		IP:          ip,
		UserAgent:   ua,
		RequestID:   reqID,
	})

	if err := tx.Commit(ctx); err != nil {
		return err
	}

	s.resolver.InvalidateUser(ctx, tenantID, userID)
	return nil
}

// AddRole adds a single role to a user (idempotent).
func (s *Service) AddRole(ctx context.Context, r *http.Request, tenantID, userID, roleID, actorID string) error {
	exists, err := s.repo.RoleExists(ctx, tenantID, roleID)
	if err != nil {
		return err
	}
	if !exists {
		return ErrRoleNotFound
	}

	if _, err := s.GetByID(ctx, tenantID, userID); err != nil {
		return err
	}

	tx, err := s.db.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if err := s.repo.AddRole(ctx, tx, tenantID, userID, roleID, actorID); err != nil {
		return err
	}

	ip, ua, reqID := audit.EventFromRequest(r)
	uid := actorID
	tid := tenantID
	_ = s.auditor.Record(ctx, tx, audit.Event{
		TenantID:    &tid,
		ActorUserID: &uid,
		Action:      "user.role_assign",
		TargetType:  "user",
		TargetID:    &userID,
		Metadata:    map[string]any{"role_id": roleID},
		Success:     true,
		IP:          ip,
		UserAgent:   ua,
		RequestID:   reqID,
	})

	if err := tx.Commit(ctx); err != nil {
		return err
	}

	s.resolver.InvalidateUser(ctx, tenantID, userID)
	return nil
}

// RemoveRole removes a single role from a user.
func (s *Service) RemoveRole(ctx context.Context, r *http.Request, tenantID, userID, roleID, actorID string) error {
	exists, err := s.repo.RoleExists(ctx, tenantID, roleID)
	if err != nil {
		return err
	}
	if !exists {
		return ErrRoleNotFound
	}

	if _, err := s.GetByID(ctx, tenantID, userID); err != nil {
		return err
	}

	tx, err := s.db.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if err := s.repo.RemoveRole(ctx, tx, tenantID, userID, roleID); err != nil {
		return err
	}

	ip, ua, reqID := audit.EventFromRequest(r)
	uid := actorID
	tid := tenantID
	_ = s.auditor.Record(ctx, tx, audit.Event{
		TenantID:    &tid,
		ActorUserID: &uid,
		Action:      "user.role_unassign",
		TargetType:  "user",
		TargetID:    &userID,
		Metadata:    map[string]any{"role_id": roleID},
		Success:     true,
		IP:          ip,
		UserAgent:   ua,
		RequestID:   reqID,
	})

	if err := tx.Commit(ctx); err != nil {
		return err
	}

	s.resolver.InvalidateUser(ctx, tenantID, userID)
	return nil
}
