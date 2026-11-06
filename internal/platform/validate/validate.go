// Package validate provides a shared validator instance with custom rules.
package validate

import (
	"sync"
	"unicode"

	"github.com/go-playground/validator/v10"
)

var (
	once     sync.Once
	instance *validator.Validate
)

// Get returns the singleton validator with custom rules registered.
func Get() *validator.Validate {
	once.Do(func() {
		instance = validator.New()
		// Register password policy validator
		_ = instance.RegisterValidation("password_policy", validatePasswordPolicy)
	})
	return instance
}

// validatePasswordPolicy enforces: min 10 chars, max 72 bytes, at least one letter and one digit.
func validatePasswordPolicy(fl validator.FieldLevel) bool {
	s := fl.Field().String()
	b := []byte(s)
	if len(s) < 10 || len(b) > 72 {
		return false
	}
	var hasLetter, hasDigit bool
	for _, r := range s {
		if unicode.IsLetter(r) {
			hasLetter = true
		}
		if unicode.IsDigit(r) {
			hasDigit = true
		}
	}
	return hasLetter && hasDigit
}

