package audit

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/multi_tenante_ums/internal/middleware"
	"github.com/multi_tenante_ums/internal/platform/httpx"
)

// Repository provides read access to audit logs.
type Repository struct {
	db *pgxpool.Pool
}

// NewRepository creates a new audit Repository.
func NewRepository(db *pgxpool.Pool) *Repository {
	return &Repository{db: db}
}

// ListFilter holds filters for listing audit logs.
type ListFilter struct {
	TenantID   string
	ActorID    string
	Action     string
	TargetType string
	TargetID   string
	From       *time.Time
	To         *time.Time
	Limit      int
	Cursor     *Cursor // keyset cursor
}

// Cursor is a decoded keyset cursor.
type Cursor struct {
	CreatedAt time.Time
	ID        int64
}

// DecodeCursor decodes a base64-opaque cursor string.
func DecodeCursor(s string) (*Cursor, error) {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("audit: invalid cursor")
	}
	parts := strings.SplitN(string(b), ",", 2)
	if len(parts) != 2 {
		return nil, fmt.Errorf("audit: invalid cursor format")
	}
	t, err := time.Parse(time.RFC3339Nano, parts[0])
	if err != nil {
		return nil, fmt.Errorf("audit: invalid cursor time")
	}
	id, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil {
		return nil, fmt.Errorf("audit: invalid cursor id")
	}
	return &Cursor{CreatedAt: t, ID: id}, nil
}

// EncodeCursor encodes a cursor to a base64 string.
func EncodeCursor(createdAt time.Time, id int64) string {
	raw := createdAt.UTC().Format(time.RFC3339Nano) + "," + strconv.FormatInt(id, 10)
	return base64.StdEncoding.EncodeToString([]byte(raw))
}

// ListResult holds a page of audit logs and the next cursor.
type ListResult struct {
	Logs       []Log
	NextCursor *string
}

// List fetches audit logs using keyset pagination.
func (repo *Repository) List(ctx context.Context, f ListFilter) (*ListResult, error) {
	if f.Limit <= 0 || f.Limit > 100 {
		f.Limit = 20
	}

	args := []any{f.TenantID}
	conditions := []string{"al.tenant_id = $1"}
	idx := 2

	if f.ActorID != "" {
		conditions = append(conditions, fmt.Sprintf("al.actor_user_id = $%d", idx))
		args = append(args, f.ActorID)
		idx++
	}
	if f.Action != "" {
		conditions = append(conditions, fmt.Sprintf("al.action = $%d", idx))
		args = append(args, f.Action)
		idx++
	}
	if f.TargetType != "" {
		conditions = append(conditions, fmt.Sprintf("al.target_type = $%d", idx))
		args = append(args, f.TargetType)
		idx++
	}
	if f.TargetID != "" {
		conditions = append(conditions, fmt.Sprintf("al.target_id = $%d", idx))
		args = append(args, f.TargetID)
		idx++
	}
	if f.From != nil {
		conditions = append(conditions, fmt.Sprintf("al.created_at >= $%d", idx))
		args = append(args, f.From)
		idx++
	}
	if f.To != nil {
		conditions = append(conditions, fmt.Sprintf("al.created_at <= $%d", idx))
		args = append(args, f.To)
		idx++
	}
	if f.Cursor != nil {
		conditions = append(conditions, fmt.Sprintf("(al.created_at, al.id) < ($%d, $%d)", idx, idx+1))
		args = append(args, f.Cursor.CreatedAt, f.Cursor.ID)
		idx += 2
	}

	where := strings.Join(conditions, " AND ")
	query := fmt.Sprintf(`
		SELECT al.id, al.tenant_id, al.actor_user_id, al.action, al.target_type, al.target_id,
		       al.metadata, al.success, al.ip, al.user_agent, al.request_id, al.created_at
		FROM audit_logs al
		WHERE %s
		ORDER BY al.created_at DESC, al.id DESC
		LIMIT $%d`, where, idx)
	args = append(args, f.Limit+1)

	rows, err := repo.db.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("audit: list: %w", err)
	}
	defer rows.Close()

	logs := make([]Log, 0, f.Limit)
	for rows.Next() {
		var l Log
		var meta []byte
		if err := rows.Scan(
			&l.ID, &l.TenantID, &l.ActorUserID, &l.Action, &l.TargetType, &l.TargetID,
			&meta, &l.Success, &l.IP, &l.UserAgent, &l.RequestID, &l.CreatedAt,
		); err != nil {
			return nil, fmt.Errorf("audit: list scan: %w", err)
		}
		l.Metadata = make(map[string]any)
		if len(meta) > 0 {
			_ = json.Unmarshal(meta, &l.Metadata)
		}
		logs = append(logs, l)
	}

	result := &ListResult{Logs: logs}
	if len(logs) > f.Limit {
		result.Logs = logs[:f.Limit]
		last := result.Logs[len(result.Logs)-1]
		cursor := EncodeCursor(last.CreatedAt, last.ID)
		result.NextCursor = &cursor
	}
	return result, nil
}

// Handler is the HTTP handler for audit log routes.
type Handler struct {
	repo *Repository
}

// NewHandler creates a new audit Handler.
func NewHandler(repo *Repository) *Handler {
	return &Handler{repo: repo}
}

// ListAuditLogs handles GET /api/v1/audit-logs with keyset pagination.
func (h *Handler) ListAuditLogs(w http.ResponseWriter, r *http.Request) {
	auth := middleware.MustAuthContext(r.Context())

	q := r.URL.Query()
	limit := 20
	if ls := q.Get("limit"); ls != "" {
		if v, err := strconv.Atoi(ls); err == nil && v > 0 && v <= 100 {
			limit = v
		}
	}

	filter := ListFilter{
		TenantID:   auth.TenantID,
		ActorID:    q.Get("actor_id"),
		Action:     q.Get("action"),
		TargetType: q.Get("target_type"),
		TargetID:   q.Get("target_id"),
		Limit:      limit,
	}

	if fromStr := q.Get("from"); fromStr != "" {
		t, err := time.Parse(time.RFC3339, fromStr)
		if err == nil {
			filter.From = &t
		}
	}
	if toStr := q.Get("to"); toStr != "" {
		t, err := time.Parse(time.RFC3339, toStr)
		if err == nil {
			filter.To = &t
		}
	}
	if cursorStr := q.Get("cursor"); cursorStr != "" {
		c, err := DecodeCursor(cursorStr)
		if err != nil {
			httpx.WriteError(w, r, http.StatusBadRequest, httpx.ErrCodeValidationFailed, "invalid cursor")
			return
		}
		filter.Cursor = c
	}

	result, err := h.repo.List(r.Context(), filter)
	if err != nil {
		httpx.WriteError(w, r, http.StatusInternalServerError, httpx.ErrCodeInternal, "failed to list audit logs")
		return
	}

	if result.Logs == nil {
		result.Logs = []Log{}
	}

	httpx.WriteJSON(w, http.StatusOK, KeysetResponse{
		Data:       result.Logs,
		NextCursor: result.NextCursor,
	})
}

// KeysetResponse is the response shape for audit log listing.
type KeysetResponse struct {
	Data       []Log   `json:"data"`
	NextCursor *string `json:"next_cursor"`
}
