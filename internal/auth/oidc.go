package auth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// OIDCConfig configures an OpenID Connect relying party.
type OIDCConfig struct {
	Issuer       string
	ClientID     string
	ClientSecret string
	RedirectURL  string
	TenantSlug   string
}

// OIDCClient is a minimal OpenID Connect relying party implementing the
// authorization-code flow with PKCE and RS256 ID-token verification.
type OIDCClient struct {
	cfg       OIDCConfig
	http      *http.Client
	discovery oidcDiscovery
	jwks      jwkSet
}

type oidcDiscovery struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	UserInfoEndpoint      string `json:"userinfo_endpoint"`
	JWKSURI               string `json:"jwks_uri"`
}

type jwkSet struct {
	Keys []jwk `json:"keys"`
}

type jwk struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	N   string `json:"n"`
	E   string `json:"e"`
}

// NewOIDCClient performs discovery and fetches the provider's JWKS.
func NewOIDCClient(cfg OIDCConfig) (*OIDCClient, error) {
	if cfg.Issuer == "" || cfg.ClientID == "" || cfg.RedirectURL == "" {
		return nil, errors.New("oidc: issuer, client_id, and redirect_url are required")
	}
	c := &OIDCClient{cfg: cfg, http: &http.Client{Timeout: 10 * time.Second}}

	wellKnown := strings.TrimRight(cfg.Issuer, "/") + "/.well-known/openid-configuration"
	if err := c.getJSON(wellKnown, &c.discovery); err != nil {
		return nil, fmt.Errorf("oidc discovery: %w", err)
	}
	if c.discovery.AuthorizationEndpoint == "" || c.discovery.TokenEndpoint == "" {
		return nil, errors.New("oidc: incomplete discovery document")
	}
	if err := c.getJSON(c.discovery.JWKSURI, &c.jwks); err != nil {
		return nil, fmt.Errorf("oidc jwks: %w", err)
	}
	return c, nil
}

func (c *OIDCClient) getJSON(u string, v any) error {
	resp, err := c.http.Get(u)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("http %s", resp.Status)
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(v)
}

// PKCE is an S256 proof key.
type PKCE struct {
	Verifier  string
	Challenge string
}

// NewPKCE generates a random code verifier and its S256 challenge.
func NewPKCE() PKCE {
	verifier := randomB64(64)
	h := sha256.Sum256([]byte(verifier))
	return PKCE{
		Verifier:  verifier,
		Challenge: base64.RawURLEncoding.EncodeToString(h[:]),
	}
}

func randomB64(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// AuthURL builds the authorization URL for the code flow.
func (c *OIDCClient) AuthURL(state, nonce string, pkce PKCE) string {
	q := url.Values{}
	q.Set("client_id", c.cfg.ClientID)
	q.Set("response_type", "code")
	q.Set("scope", "openid email profile")
	q.Set("redirect_uri", c.cfg.RedirectURL)
	q.Set("state", state)
	q.Set("nonce", nonce)
	q.Set("code_challenge", pkce.Challenge)
	q.Set("code_challenge_method", "S256")
	return c.discovery.AuthorizationEndpoint + "?" + q.Encode()
}

// OIDCIdentity is the verified identity extracted from the ID token.
type OIDCIdentity struct {
	Sub           string
	Email         string
	EmailVerified bool
	Name          string
}

type tokenResponse struct {
	AccessToken string `json:"access_token"`
	IDToken     string `json:"id_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
	Error       string `json:"error"`
	ErrorDesc   string `json:"error_description"`
}

// Exchange redeems an authorization code and verifies the returned ID token.
func (c *OIDCClient) Exchange(ctx context.Context, code, verifier, nonce string) (*OIDCIdentity, error) {
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", c.cfg.RedirectURL)
	form.Set("client_id", c.cfg.ClientID)
	form.Set("client_secret", c.cfg.ClientSecret)
	form.Set("code_verifier", verifier)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.discovery.TokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("oidc token: http %s", resp.Status)
	}

	var tr tokenResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&tr); err != nil {
		return nil, err
	}
	if tr.Error != "" {
		return nil, fmt.Errorf("oidc token: %s: %s", tr.Error, tr.ErrorDesc)
	}
	if tr.IDToken == "" {
		return nil, errors.New("oidc token: missing id_token")
	}
	return c.verifyIDToken(tr.IDToken, nonce)
}

// verifyIDToken validates signature, issuer, audience and nonce.
func (c *OIDCClient) verifyIDToken(raw, nonce string) (*OIDCIdentity, error) {
	parser := jwt.NewParser(jwt.WithValidMethods([]string{"RS256", "RS384", "RS512"}), jwt.WithIssuer(c.discovery.Issuer), jwt.WithAudience(c.cfg.ClientID))

	claims := jwt.MapClaims{}
	tok, err := parser.ParseWithClaims(raw, claims, func(t *jwt.Token) (any, error) {
		kid, _ := t.Header["kid"].(string)
		for _, k := range c.jwks.Keys {
			if k.Kid != kid {
				continue
			}
			return k.rsaPublicKey()
		}
		return nil, errors.New("oidc: no matching signing key")
	})
	if err != nil {
		return nil, fmt.Errorf("oidc id_token: %w", err)
	}
	if !tok.Valid {
		return nil, errors.New("oidc id_token: invalid")
	}

	gotNonce, _ := claims["nonce"].(string)
	if nonce != "" && gotNonce != nonce {
		return nil, errors.New("oidc id_token: nonce mismatch")
	}

	id := &OIDCIdentity{
		Sub:   str(claims["sub"]),
		Email: str(claims["email"]),
		Name:  str(claims["name"]),
	}
	if v, ok := claims["email_verified"].(bool); ok {
		id.EmailVerified = v
	}
	if id.Email == "" {
		return nil, errors.New("oidc id_token: missing email claim")
	}
	return id, nil
}

func (k jwk) rsaPublicKey() (*rsa.PublicKey, error) {
	nBytes, err := base64.RawURLEncoding.DecodeString(k.N)
	if err != nil {
		return nil, err
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(k.E)
	if err != nil {
		return nil, err
	}
	n := new(big.Int).SetBytes(nBytes)
	e := new(big.Int).SetBytes(eBytes)
	if !e.IsInt64() {
		return nil, errors.New("invalid RSA exponent")
	}
	return &rsa.PublicKey{N: n, E: int(e.Int64())}, nil
}

func str(v any) string {
	s, _ := v.(string)
	return s
}
