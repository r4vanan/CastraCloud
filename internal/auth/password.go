// Package auth provides password hashing, JWT issuance/verification, and
// role-based access control for the CastraCloud control plane.
package auth

import (
	"errors"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

// ValidatePassword enforces the baseline password policy for local accounts.
func ValidatePassword(password string) error {
	if len(password) < 12 {
		return errors.New("password must be at least 12 characters")
	}
	var upper, lower, digit bool
	for _, r := range password {
		switch {
		case r >= 'A' && r <= 'Z':
			upper = true
		case r >= 'a' && r <= 'z':
			lower = true
		case r >= '0' && r <= '9':
			digit = true
		}
	}
	if !upper || !lower || !digit {
		return errors.New("password must include uppercase, lowercase, and numeric characters")
	}
	if strings.TrimSpace(password) == "" {
		return errors.New("password must not be empty")
	}
	return nil
}

// HashPassword returns a bcrypt hash of the given plaintext password.
func HashPassword(password string) (string, error) {
	if err := ValidatePassword(password); err != nil {
		return "", err
	}
	b, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// CheckPassword reports whether the plaintext password matches the bcrypt hash.
func CheckPassword(hash, password string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil
}
