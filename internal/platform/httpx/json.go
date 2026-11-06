// Package httpx provides HTTP helpers: JSON encoding/decoding, error responses,
// pagination, and request-id extraction.
package httpx

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"

	"github.com/go-playground/validator/v10"
)

// WriteJSON writes v as a JSON body with the given status code.
func WriteJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		slog.Error("httpx: encode json", "err", err)
	}
}

// DecodeJSON decodes the request body into v. It disallows unknown fields and
// returns a user-facing error suitable for a 400 / 422 response.
func DecodeJSON(r *http.Request, v any) error {
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}

// ---------------- Error types ----------------

// APIError is the standard error envelope.
type APIError struct {
	Code      string        `json:"code"`
	Message   string        `json:"message"`
	Details   []FieldError  `json:"details,omitempty"`
	RequestID string        `json:"request_id,omitempty"`
}

// FieldError describes one validation failure.
type FieldError struct {
	Field string `json:"field"`
	Issue string `json:"issue"`
}

type errorResponse struct {
	Error APIError `json:"error"`
}

// Error codes.
const (
	ErrCodeValidationFailed    = "VALIDATION_FAILED"
	ErrCodeInvalidCredentials  = "INVALID_CREDENTIALS"
	ErrCodeUnauthenticated     = "UNAUTHENTICATED"
	ErrCodeForbidden           = "FORBIDDEN"
	ErrCodeTenantSuspended     = "TENANT_SUSPENDED"
	ErrCodeNotFound            = "NOT_FOUND"
	ErrCodeConflict            = "CONFLICT"
	ErrCodeEmailAlreadyExists  = "EMAIL_ALREADY_EXISTS"
	ErrCodeSystemRoleImmutable = "SYSTEM_ROLE_IMMUTABLE"
	ErrCodeSelfDelete          = "SELF_DELETE_FORBIDDEN"
	ErrCodeRateLimited         = "RATE_LIMITED"
	ErrCodeInternal            = "INTERNAL_ERROR"
	ErrCodeUnknownField        = "UNKNOWN_FIELD"
	ErrCodeRoleNotFound        = "ROLE_NOT_FOUND"
)

// WriteError writes a structured error response.
func WriteError(w http.ResponseWriter, r *http.Request, status int, code, message string, details ...FieldError) {
	WriteJSON(w, status, errorResponse{
		Error: APIError{
			Code:      code,
			Message:   message,
			Details:   details,
			RequestID: RequestIDFromCtx(r.Context()),
		},
	})
}

// WriteValidationError translates validator.ValidationErrors into field errors.
func WriteValidationError(w http.ResponseWriter, r *http.Request, err error) {
	var ve validator.ValidationErrors
	if errors.As(err, &ve) {
		fields := make([]FieldError, 0, len(ve))
		for _, f := range ve {
			fields = append(fields, FieldError{
				Field: fieldName(f.Field()),
				Issue: validationMessage(f),
			})
		}
		WriteError(w, r, http.StatusUnprocessableEntity, ErrCodeValidationFailed, "Request validation failed", fields...)
		return
	}
	WriteError(w, r, http.StatusUnprocessableEntity, ErrCodeValidationFailed, err.Error())
}

func fieldName(s string) string {
	// Convert from struct field name to JSON-like snake_case if needed
	return s
}

func validationMessage(f validator.FieldError) string {
	switch f.Tag() {
	case "required":
		return "is required"
	case "email":
		return "must be a valid email"
	case "min":
		return "is too short (min " + f.Param() + ")"
	case "max":
		return "is too long (max " + f.Param() + ")"
	case "oneof":
		return "must be one of: " + f.Param()
	case "uuid4":
		return "must be a valid UUID"
	case "uuid":
		return "must be a valid UUID"
	case "password_policy":
		return "must be at least 10 characters and contain a letter and a digit"
	default:
		return "is invalid"
	}
}

// WriteDecodeError translates JSON decode errors into appropriate responses.
func WriteDecodeError(w http.ResponseWriter, r *http.Request, err error) {
	if err == nil {
		return
	}
	var syntaxErr *json.SyntaxError
	if errors.As(err, &syntaxErr) {
		WriteError(w, r, http.StatusBadRequest, ErrCodeValidationFailed, "malformed JSON")
		return
	}
	var unmarshalErr *json.UnmarshalTypeError
	if errors.As(err, &unmarshalErr) {
		WriteError(w, r, http.StatusBadRequest, ErrCodeValidationFailed, "wrong type for field "+unmarshalErr.Field)
		return
	}
	// DisallowUnknownFields sends a plain string error starting with "json: unknown field"
	if err.Error() != "" {
		WriteError(w, r, http.StatusBadRequest, ErrCodeUnknownField, err.Error())
		return
	}
	WriteError(w, r, http.StatusBadRequest, ErrCodeValidationFailed, "invalid request body")
}

