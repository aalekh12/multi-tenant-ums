// Package audit provides the audit log recorder and repository.
package audit

import (
	"context"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/multi_tenante_ums/internal/middleware"
	"github.com/multi_tenante_ums/internal/platform/httpx"
)

// Log represents one audit log entry.
type Log struct {
	ID          int64          `json:"id"`
	TenantID    *string        `json:"tenant_id"`
	ActorUserID *string        `json:"actor_user_id"`
	Action      string         `json:"action"`
	TargetType  string         `json:"target_type"`
	TargetID    *string        `json:"target_id"`
	Metadata    map[string]any `json:"metadata"`
	Success     bool           `json:"success"`
	IP          *string        `json:"ip"`
	UserAgent   *string        `json:"user_agent"`
	RequestID   *string        `json:"request_id"`
	CreatedAt   time.Time      `json:"created_at"`
}

// Event describes an audit event to be recorded.
type Event struct {
	TenantID    *string
	ActorUserID *string
	Action      string
	TargetType  string
	TargetID    *string
	Metadata    map[string]any
	Success     bool
	IP          *string
	UserAgent   *string
	RequestID   *string
}

// Recorder writes audit events into the database.
type Recorder struct{}

// NewRecorder returns a new Recorder.
func NewRecorder() *Recorder { return &Recorder{} }

// Record inserts an audit event using the provided transaction.
func (rec *Recorder) Record(ctx context.Context, q interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
}, evt Event) error {
	meta := evt.Metadata
	if meta == nil {
		meta = map[string]any{}
	}
	_, err := q.Exec(ctx, `
		INSERT INTO audit_logs
			(tenant_id, actor_user_id, action, target_type, target_id, metadata, success, ip, user_agent, request_id)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
		evt.TenantID, evt.ActorUserID, evt.Action, evt.TargetType, evt.TargetID,
		meta, evt.Success, evt.IP, evt.UserAgent, evt.RequestID,
	)
	return err
}

func extractIP(r *http.Request) string {
	if r == nil {
		return ""
	}
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		ip := strings.TrimSpace(parts[0])
		if net.ParseIP(ip) != nil {
			return ip
		}
	}
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		ip := strings.TrimSpace(xri)
		if net.ParseIP(ip) != nil {
			return ip
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil && net.ParseIP(host) != nil {
		return host
	}
	if net.ParseIP(r.RemoteAddr) != nil {
		return r.RemoteAddr
	}
	return ""
}

// EventFromRequest populates common request fields from an http.Request and AuthContext.
func EventFromRequest(r *http.Request) (ip *string, ua *string, reqID *string) {
	if r == nil {
		return nil, nil, nil
	}
	if ipStr := extractIP(r); ipStr != "" {
		ip = &ipStr
	}
	if uaStr := r.UserAgent(); uaStr != "" {
		ua = &uaStr
	}
	if ridStr := httpx.RequestIDFromCtx(r.Context()); ridStr != "" {
		reqID = &ridStr
	}
	return
}

// ActorFromCtx extracts actor info from the middleware AuthContext.
func ActorFromCtx(ctx context.Context) (tenantID *string, userID *string) {
	auth, ok := middleware.AuthContextFromCtx(ctx)
	if ok {
		tid := auth.TenantID
		uid := auth.UserID
		return &tid, &uid
	}
	return nil, nil
}

// Ptr returns a pointer to the given value.
func Ptr[T any](v T) *T { return &v }
