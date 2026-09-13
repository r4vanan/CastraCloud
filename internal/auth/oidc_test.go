package auth

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"math/big"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestPKCE(t *testing.T) {
	pkce := NewPKCE()
	if len(pkce.Verifier) < 43 || len(pkce.Verifier) > 128 {
		t.Fatalf("verifier length out of range: %d", len(pkce.Verifier))
	}
	if pkce.Challenge == "" {
		t.Fatal("empty challenge")
	}
}

func TestVerifyIDToken(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	c := &OIDCClient{
		cfg: OIDCConfig{ClientID: "test-client"},
		discovery: oidcDiscovery{Issuer: "https://issuer.example.com"},
		jwks: jwkSet{Keys: []jwk{{
			Kty: "RSA",
			Kid: "kid-1",
			Alg: "RS256",
			N:   base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
			E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
		}}},
	}

	claims := jwt.MapClaims{
		"sub":            "user-123",
		"email":          "alice@example.com",
		"email_verified": true,
		"name":           "Alice",
		"nonce":          "n-1",
		"iss":            "https://issuer.example.com",
		"aud":            "test-client",
		"exp":            time.Now().Add(time.Hour).Unix(),
		"iat":            time.Now().Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = "kid-1"
	raw, err := token.SignedString(key)
	if err != nil {
		t.Fatal(err)
	}

	id, err := c.verifyIDToken(raw, "n-1")
	if err != nil {
		t.Fatalf("verify failed: %v", err)
	}
	if id.Email != "alice@example.com" || id.Sub != "user-123" || id.Name != "Alice" {
		t.Fatalf("unexpected identity: %+v", id)
	}

	// nonce mismatch must fail
	if _, err := c.verifyIDToken(raw, "wrong"); err == nil {
		t.Fatal("expected nonce mismatch error")
	}
}
