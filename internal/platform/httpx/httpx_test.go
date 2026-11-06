package httpx_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/yourusername/usermgmt/internal/platform/httpx"
)

type sampleBody struct {
	Name string `json:"name"`
	Age  int    `json:"age"`
}

func TestDecodeJSON_DisallowUnknownFields(t *testing.T) {
	// Payload with unknown field "extra"
	payload := `{"name":"alice","age":30,"extra":"not_allowed"}`
	req := httptest.NewRequest(http.MethodPost, "/test", bytes.NewBufferString(payload))

	var body sampleBody
	err := httpx.DecodeJSON(req, &body)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown field")
}

func TestDecodeJSON_Valid(t *testing.T) {
	payload := `{"name":"alice","age":30}`
	req := httptest.NewRequest(http.MethodPost, "/test", bytes.NewBufferString(payload))

	var body sampleBody
	err := httpx.DecodeJSON(req, &body)
	require.NoError(t, err)
	assert.Equal(t, "alice", body.Name)
	assert.Equal(t, 30, body.Age)
}

func TestPagination_ParseAndMeta(t *testing.T) {
	// Defaults
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	p := httpx.ParsePagination(req)
	assert.Equal(t, 1, p.Page)
	assert.Equal(t, 20, p.PageSize)

	// Custom values with capping at 100
	req = httptest.NewRequest(http.MethodGet, "/test?page=3&page_size=150", nil)
	p = httpx.ParsePagination(req)
	assert.Equal(t, 3, p.Page)
	assert.Equal(t, 100, p.PageSize)

	// Meta calculation
	meta := httpx.NewPaginationMeta(p, 250)
	assert.Equal(t, 3, meta.Page)
	assert.Equal(t, 100, meta.PageSize)
	assert.Equal(t, int64(250), meta.Total)
	assert.Equal(t, 3, meta.TotalPages) // ceil(250/100) = 3
}

func TestWriteError_Format(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)

	httpx.WriteError(rec, req, http.StatusBadRequest, httpx.ErrCodeValidationFailed, "Request failed",
		httpx.FieldError{Field: "email", Issue: "must be a valid email"},
	)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Equal(t, "application/json", rec.Header().Get("Content-Type"))

	var resp struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
			Details []struct {
				Field string `json:"field"`
				Issue string `json:"issue"`
			} `json:"details"`
		} `json:"error"`
	}
	err := json.Unmarshal(rec.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, httpx.ErrCodeValidationFailed, resp.Error.Code)
	assert.Equal(t, "Request failed", resp.Error.Message)
	require.Len(t, resp.Error.Details, 1)
	assert.Equal(t, "email", resp.Error.Details[0].Field)
	assert.Equal(t, "must be a valid email", resp.Error.Details[0].Issue)
}

func TestRequestIDMiddleware(t *testing.T) {
	handler := httpx.RequestIDMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reqID := httpx.RequestIDFromCtx(r.Context())
		assert.NotEmpty(t, reqID)
		w.WriteHeader(http.StatusOK)
	}))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	handler.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
}

