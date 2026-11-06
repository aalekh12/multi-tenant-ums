package validate_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/yourusername/usermgmt/internal/platform/validate"
)

type passwordTest struct {
	Password string `validate:"password_policy"`
}

func TestValidate_PasswordPolicy(t *testing.T) {
	v := validate.Get()

	tests := []struct {
		name    string
		pwd     string
		wantErr bool
	}{
		{"Valid password 10 chars", "Password12", false},
		{"Valid complex password", "S3cure!P@ssword2026", false},
		{"Too short (< 10 chars)", "Pass1", true},
		{"No digit", "PasswordOnly", true},
		{"No letter", "123456789012", true},
		{"Over 72 bytes", strings.Repeat("A1", 37), true}, // 74 chars
		{"Exactly 72 bytes", strings.Repeat("A1", 36), false}, // 72 chars
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := v.Struct(&passwordTest{Password: tt.pwd})
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

