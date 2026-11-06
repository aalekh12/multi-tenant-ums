package auth

import (
	"context"
	"crypto/sha256"
	"fmt"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/yourusername/usermgmt/internal/audit"
	"github.com/yourusername/usermgmt/internal/platform/cache"
	"github.com/yourusername/usermgmt/internal/platform/jwtx"
	"github.com/yourusername/usermgmt/internal/platform/password"
)

// ErrInvalidCredentials is returned for any credential failure (equalized message).
var ErrInvalidCredentials = fmt.Errorf("invalid credentials")

// ErrTenantSuspended is returned when the tenant is suspended.
var ErrTenantSuspended = fmt.Errorf("tenant is suspended")

// ErrRateLimit is returned when the login rate limit is exceeded.
var ErrRateLimit = fmt.Errorf("rate limit exceeded")

// ErrRefreshReuse is returned when a refresh token is replayed.
var ErrRefreshReuse = fmt.Errorf("refresh token reuse detected")

// Config holds service configuration.
type Config struct {
	AccessTTL  time.Duration
	RefreshTTL time.Duration
}

// Service holds auth business logic.
type Service struct {
	db      *pgxpool.Pool
	repo    *Repo
	issuer  *jwtx.Issuer
	hasher  *password.Hasher
	cache   cache.Cache
	auditor *audit.Recorder
	cfg     Config
}

// NewService creates a new auth Service.
func NewService(
	db *pgxpool.Pool,
	repo *Repo,
	issuer *jwtx.Issuer,
	hasher *password.Hasher,
	c cache.Cache,
	auditor *audit.Recorder,
	cfg Config,
) *Service {
	return &Service{
		db:      db,
		repo:    repo,
		issuer:  issuer,
		hasher:  hasher,
		cache:   c,
		auditor: auditor,
		cfg:     cfg,
	}
}

// rateLimitKey returns the cache key for login rate limiting.
func rateLimitKey(ip, email string) string {
	return fmt.Sprintf("ratelimit:login:%s:%s", ip, email)
}

// Login authenticates a user against a tenant and returns token pair.
func (s *Service) Login(ctx context.Context, r *http.Request, in *LoginInput) (*TokenPair, error) {
	// Rate limit: 10 attempts/min per (IP+email)
	ip, _, _ := audit.EventFromRequest(r)
	ipStr := ""
	if ip != nil {
		ipStr = *ip
	}
	rlKey := rateLimitKey(ipStr, in.Email)
	count, _ := s.cache.Increment(ctx, rlKey, time.Minute)
	if count > 10 {
		return nil, ErrRateLimit
	}

	// Look up tenant by code
	tenant, err := s.repo.GetTenantByCode(ctx, in.TenantCode)
	recordTenantID := (*string)(nil)
	if tenant != nil {
		tid := tenant.ID
		recordTenantID = &tid
	}

	// Look up user by email
	user, err2 := s.repo.FindUserByEmail(ctx, in.Email)

	// Always run bcrypt compare (use dummy hash if user not found)
	hashToCompare := password.DummyHash
	if user != nil {
		hashToCompare = user.PasswordHash
	}
	pwErr := s.hasher.Compare(hashToCompare, in.Password)

	// Determine success
	var loginErr error
	switch {
	case err != nil || tenant == nil:
		loginErr = ErrInvalidCredentials
	case err2 != nil || user == nil:
		loginErr = ErrInvalidCredentials
	case pwErr != nil:
		loginErr = ErrInvalidCredentials
	default:
		// Check membership
		mem, memErr := s.repo.GetMembership(ctx, user.ID, tenant.ID)
		if memErr != nil || mem == nil || mem.Status != "active" {
			loginErr = ErrInvalidCredentials
		} else if tenant.Status == "suspended" {
			loginErr = ErrTenantSuspended
		}
	}

	// Write audit
	ip2, ua, reqID := audit.EventFromRequest(r)
	success := loginErr == nil
	emailHash := fmt.Sprintf("%x", sha256.Sum256([]byte(in.Email)))
	auditEvt := audit.Event{
		TenantID:    recordTenantID,
		ActorUserID: nil,
		Action:      "auth.login",
		TargetType:  "session",
		Metadata:    map[string]any{"email_hash": emailHash},
		Success:     success,
		IP:          ip2,
		UserAgent:   ua,
		RequestID:   reqID,
	}
	if success && user != nil {
		uid := user.ID
		auditEvt.ActorUserID = &uid
	}
	// Write audit asynchronously (no tx for failed logins)
	go func() {
		_ = s.auditor.Record(context.Background(), s.db, auditEvt)
	}()

	if loginErr != nil {
		return nil, loginErr
	}

	// Issue tokens
	familyID := uuid.New().String()
	accessToken, _, accessErr := s.issuer.IssueAccess(user.ID, tenant.ID, familyID, s.cfg.AccessTTL)
	if accessErr != nil {
		return nil, fmt.Errorf("auth: issue access token: %w", accessErr)
	}
	refreshJTI := uuid.New().String()
	refreshToken, refreshErr := s.issuer.IssueRefresh(user.ID, tenant.ID, familyID, refreshJTI, s.cfg.RefreshTTL)
	if refreshErr != nil {
		return nil, fmt.Errorf("auth: issue refresh token: %w", refreshErr)
	}

	// Store refresh token
	ua2 := r.UserAgent()
	rt := &RefreshToken{
		JTI:       refreshJTI,
		FamilyID:  familyID,
		UserID:    user.ID,
		TenantID:  tenant.ID,
		ExpiresAt: time.Now().Add(s.cfg.RefreshTTL),
		IP:        ip2,
		UserAgent: &ua2,
	}

	tx, txErr := s.db.Begin(ctx)
	if txErr != nil {
		return nil, fmt.Errorf("auth: begin tx: %w", txErr)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if err := s.repo.InsertRefreshToken(ctx, tx, rt); err != nil {
		return nil, fmt.Errorf("auth: insert refresh token: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("auth: commit: %w", err)
	}

	return &TokenPair{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresIn:    int(s.cfg.AccessTTL.Seconds()),
	}, nil
}

// Refresh rotates a refresh token. Returns new pair or error (including reuse detection).
func (s *Service) Refresh(ctx context.Context, r *http.Request, refreshTokenStr string) (*TokenPair, error) {
	// Parse and validate refresh token
	claims, err := s.issuer.Parse(refreshTokenStr, jwtx.TypeRefresh)
	if err != nil {
		return nil, ErrInvalidCredentials
	}

	// Load from DB
	rt, err := s.repo.GetRefreshToken(ctx, claims.ID)
	if err != nil || rt == nil {
		return nil, ErrInvalidCredentials
	}

	// Reuse detection: if already used or revoked → revoke whole family
	if rt.UsedAt != nil || rt.RevokedAt != nil {
		_ = s.repo.RevokeFamily(ctx, rt.FamilyID)
		ip, ua, reqID := audit.EventFromRequest(r)
		_ = s.auditor.Record(ctx, s.db, audit.Event{
			TenantID:   &rt.TenantID,
			Action:     "auth.refresh_reuse_detected",
			TargetType: "session",
			TargetID:   &rt.FamilyID,
			Success:    false,
			IP:         ip, UserAgent: ua, RequestID: reqID,
		})
		return nil, ErrRefreshReuse
	}

	// Check user, membership, tenant are still valid
	user, err := s.repo.GetUserByID(ctx, rt.UserID)
	if err != nil || user == nil {
		return nil, ErrInvalidCredentials
	}
	mem, err := s.repo.GetMembership(ctx, rt.UserID, rt.TenantID)
	if err != nil || mem == nil || mem.Status != "active" {
		return nil, ErrInvalidCredentials
	}
	tenant, err := s.repo.GetTenantByID(ctx, rt.TenantID)
	if err != nil || tenant == nil || tenant.Status == "suspended" {
		return nil, ErrTenantSuspended
	}

	// Issue new pair in a transaction
	tx, txErr := s.db.Begin(ctx)
	if txErr != nil {
		return nil, fmt.Errorf("auth: begin tx: %w", txErr)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if err := s.repo.MarkRefreshTokenUsed(ctx, tx, rt.JTI); err != nil {
		return nil, fmt.Errorf("auth: mark used: %w", err)
	}

	accessToken, _, accessErr := s.issuer.IssueAccess(rt.UserID, rt.TenantID, rt.FamilyID, s.cfg.AccessTTL)
	if accessErr != nil {
		return nil, fmt.Errorf("auth: issue access: %w", accessErr)
	}
	newJTI := uuid.New().String()
	refreshToken, refreshErr := s.issuer.IssueRefresh(rt.UserID, rt.TenantID, rt.FamilyID, newJTI, s.cfg.RefreshTTL)
	if refreshErr != nil {
		return nil, fmt.Errorf("auth: issue refresh: %w", refreshErr)
	}

	ip, ua2, _ := audit.EventFromRequest(r)
	uaStr := r.UserAgent()
	newRT := &RefreshToken{
		JTI:       newJTI,
		FamilyID:  rt.FamilyID,
		UserID:    rt.UserID,
		TenantID:  rt.TenantID,
		ExpiresAt: time.Now().Add(s.cfg.RefreshTTL),
		IP:        ip,
		UserAgent: &uaStr,
	}
	_ = ua2
	if err := s.repo.InsertRefreshToken(ctx, tx, newRT); err != nil {
		return nil, fmt.Errorf("auth: insert new refresh: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("auth: commit: %w", err)
	}

	return &TokenPair{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresIn:    int(s.cfg.AccessTTL.Seconds()),
	}, nil
}

// Logout revokes the entire refresh token family for the caller's session.
func (s *Service) Logout(ctx context.Context, r *http.Request, userID, tenantID, sessionID string) error {
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return fmt.Errorf("auth: begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if err := s.repo.RevokeFamilyTx(ctx, tx, sessionID); err != nil {
		return fmt.Errorf("auth: revoke family: %w", err)
	}

	ip, ua, reqID := audit.EventFromRequest(r)
	uid := userID
	tid := tenantID
	_ = s.auditor.Record(ctx, tx, audit.Event{
		TenantID:    &tid,
		ActorUserID: &uid,
		Action:      "auth.logout",
		TargetType:  "session",
		TargetID:    &sessionID,
		Success:     true,
		IP:          ip, UserAgent: ua, RequestID: reqID,
	})

	return tx.Commit(ctx)
}

// SwitchTenant issues a new token pair for the user scoped to a different tenant.
func (s *Service) SwitchTenant(ctx context.Context, r *http.Request, userID, currentTenantID string, in *SwitchTenantInput) (*TokenPair, error) {
	tenant, err := s.repo.GetTenantByCode(ctx, in.TenantCode)
	if err != nil || tenant == nil {
		return nil, ErrInvalidCredentials
	}
	if tenant.Status == "suspended" {
		return nil, ErrTenantSuspended
	}
	mem, err := s.repo.GetMembership(ctx, userID, tenant.ID)
	if err != nil || mem == nil || mem.Status != "active" {
		return nil, ErrInvalidCredentials
	}

	familyID := uuid.New().String()
	accessToken, _, accessErr := s.issuer.IssueAccess(userID, tenant.ID, familyID, s.cfg.AccessTTL)
	if accessErr != nil {
		return nil, fmt.Errorf("auth: issue access: %w", accessErr)
	}
	refreshJTI := uuid.New().String()
	refreshToken, refreshErr := s.issuer.IssueRefresh(userID, tenant.ID, familyID, refreshJTI, s.cfg.RefreshTTL)
	if refreshErr != nil {
		return nil, fmt.Errorf("auth: issue refresh: %w", refreshErr)
	}

	tx, txErr := s.db.Begin(ctx)
	if txErr != nil {
		return nil, fmt.Errorf("auth: begin tx: %w", txErr)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	ip, ua2, reqID := audit.EventFromRequest(r)
	uaStr := r.UserAgent()
	rt := &RefreshToken{
		JTI: refreshJTI, FamilyID: familyID,
		UserID: userID, TenantID: tenant.ID,
		ExpiresAt: time.Now().Add(s.cfg.RefreshTTL),
		IP: ip, UserAgent: &uaStr,
	}
	_ = ua2
	if err := s.repo.InsertRefreshToken(ctx, tx, rt); err != nil {
		return nil, fmt.Errorf("auth: insert refresh: %w", err)
	}

	uid := userID
	tid := tenant.ID
	_ = s.auditor.Record(ctx, tx, audit.Event{
		TenantID:    &tid,
		ActorUserID: &uid,
		Action:      "auth.switch_tenant",
		TargetType:  "session",
		Metadata:    map[string]any{"from_tenant_id": currentTenantID, "to_tenant_id": tenant.ID},
		Success:     true,
		IP:          ip, UserAgent: &uaStr, RequestID: reqID,
	})

	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("auth: commit: %w", err)
	}

	return &TokenPair{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresIn:    int(s.cfg.AccessTTL.Seconds()),
	}, nil
}

// Me returns the full profile for the authenticated user.
func (s *Service) Me(ctx context.Context, userID, tenantID string, permCodes []string) (*MeResponse, error) {
	user, err := s.repo.GetUserByID(ctx, userID)
	if err != nil || user == nil {
		return nil, ErrInvalidCredentials
	}
	tenant, err := s.repo.GetTenantByID(ctx, tenantID)
	if err != nil || tenant == nil {
		return nil, ErrInvalidCredentials
	}
	roles, err := s.repo.GetUserRoles(ctx, userID, tenantID)
	if err != nil {
		return nil, fmt.Errorf("auth: get roles: %w", err)
	}
	if roles == nil {
		roles = []RoleInfo{}
	}
	if permCodes == nil {
		permCodes = []string{}
	}
	return &MeResponse{
		User:        UserInfo{ID: user.ID, Email: user.Email, FullName: user.FullName, CreatedAt: user.CreatedAt},
		Tenant:      TenantInfo{ID: tenant.ID, Name: tenant.Name, Code: tenant.Code},
		Roles:       roles,
		Permissions: permCodes,
	}, nil
}
