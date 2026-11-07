package audit_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/multi_tenante_ums/internal/audit"
	"github.com/multi_tenante_ums/internal/platform/httpx"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCursor_EncodeAndDecode(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Microsecond)
	id := int64(123456789)

	encoded := audit.EncodeCursor(now, id)
	assert.NotEmpty(t, encoded)

	decoded, err := audit.DecodeCursor(encoded)
	require.NoError(t, err)
	assert.Equal(t, id, decoded.ID)
	assert.True(t, now.Equal(decoded.CreatedAt), "timestamps must match")
}

func TestCursor_Decode_Malformed(t *testing.T) {
	_, err := audit.DecodeCursor("not-a-valid-base64!!!")
	assert.Error(t, err)

	_, err = audit.DecodeCursor("YmFkc3RyaW5n") // "badstring" with no comma
	assert.Error(t, err)

	_, err = audit.DecodeCursor("MjAyNi0wMS0wMSxub3RhbnVtYmVy") // time,notanumber
	assert.Error(t, err)
}

type mockExecer struct {
	called bool
	sql    string
	args   []any
}

func (m *mockExecer) Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	m.called = true
	m.sql = sql
	m.args = args
	return pgconn.CommandTag{}, nil
}

func TestRecorder_Record(t *testing.T) {
	recorder := audit.NewRecorder()
	execer := &mockExecer{}

	tenantID := "tenant-1"
	actorID := "actor-1"
	targetID := "user-123"

	evt := audit.Event{
		TenantID:    &tenantID,
		ActorUserID: &actorID,
		Action:      "user.create",
		TargetType:  "user",
		TargetID:    &targetID,
		Metadata:    map[string]any{"email": "test@example.com"},
		Success:     true,
	}

	err := recorder.Record(context.Background(), execer, evt)
	require.NoError(t, err)
	assert.True(t, execer.called)
	assert.Contains(t, execer.sql, "INSERT INTO audit_logs")
	assert.Equal(t, &tenantID, execer.args[0])
	assert.Equal(t, &actorID, execer.args[1])
	assert.Equal(t, "user.create", execer.args[2])
	assert.Equal(t, "user", execer.args[3])
	assert.Equal(t, &targetID, execer.args[4])
	assert.Equal(t, true, execer.args[6])
}

func TestEventFromRequest(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.RemoteAddr = "192.168.1.100:54321"
	req.Header.Set("User-Agent", "TestClient/1.0")

	// Wrap with RequestID middleware so request id is in context
	handler := httpx.RequestIDMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip, ua, reqID := audit.EventFromRequest(r)
		require.NotNil(t, ip)
		assert.Equal(t, "192.168.1.100", *ip)

		require.NotNil(t, ua)
		assert.Equal(t, "TestClient/1.0", *ua)

		require.NotNil(t, reqID)
		assert.NotEmpty(t, *reqID)
	}))

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
}
