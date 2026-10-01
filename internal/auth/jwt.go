package auth

import (
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// MFA challenge purpose marks a short-lived token that may only complete the
// second factor of a login, never a fully authenticated session.
const PurposeMFA = "mfa"

// Claims is the JWT payload identifying an authenticated user.
type Claims struct {
	UserID   uuid.UUID `json:"user_id"`
	TenantID uuid.UUID `json:"tenant_id"`
	Role     string    `json:"role"`
	Purpose  string    `json:"purpose,omitempty"`
	jwt.RegisteredClaims
}

// IssueToken signs a JWT for the given user and tenant, returning the token
// string and its expiry time.
func IssueToken(secret string, ttl time.Duration, userID, tenantID uuid.UUID, role string) (string, time.Time, error) {
	return issueToken(secret, ttl, userID, tenantID, role, "")
}

// IssueMFAToken signs a short-lived JWT that authorizes only the second-factor
// verification step, not a full session.
func IssueMFAToken(secret string, ttl time.Duration, userID, tenantID uuid.UUID) (string, time.Time, error) {
	return issueToken(secret, ttl, userID, tenantID, "", PurposeMFA)
}

func issueToken(secret string, ttl time.Duration, userID, tenantID uuid.UUID, role, purpose string) (string, time.Time, error) {
	now := time.Now()
	exp := now.Add(ttl)
	claims := Claims{
		UserID:   userID,
		TenantID: tenantID,
		Role:     role,
		Purpose:  purpose,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   userID.String(),
			Issuer:    "castracloud",
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(exp),
		},
	}
	tok, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(secret))
	if err != nil {
		return "", time.Time{}, err
	}
	return tok, exp, nil
}

// ParseToken validates a signed JWT and returns its claims.
func ParseToken(secret, token string) (*Claims, error) {
	claims := &Claims{}
	tok, err := jwt.ParseWithClaims(token, claims, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return []byte(secret), nil
	})
	if err != nil {
		return nil, err
	}
	if !tok.Valid {
		return nil, errors.New("invalid token")
	}
	return claims, nil
}
