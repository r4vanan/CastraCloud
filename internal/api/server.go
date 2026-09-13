// Package api implements the CastraCloud control-plane HTTP API.
package api

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/castracloud/castracloud/internal/auth"
	"github.com/castracloud/castracloud/internal/store"
	"github.com/google/uuid"
)

// Server holds dependencies for the API.
type Server struct {
	db        *store.DB
	log       *slog.Logger
	jwtSecret string
	jwtTTL    time.Duration

	oidc              *auth.OIDCClient
	oidcSessions      *oidcSessionStore
	oidcTenantSlug    string
	oidcRedirectAfter string
}

// NewServer constructs an API server.
func NewServer(db *store.DB, log *slog.Logger, jwtSecret string, jwtTTL time.Duration) *Server {
	return &Server{db: db, log: log, jwtSecret: jwtSecret, jwtTTL: jwtTTL}
}

// EnableOIDC wires up an OpenID Connect relying party for SSO login.
func (s *Server) EnableOIDC(client *auth.OIDCClient, tenantSlug, redirectAfter string) {
	s.oidc = client
	s.oidcSessions = newOIDCSessionStore()
	s.oidcTenantSlug = tenantSlug
	s.oidcRedirectAfter = redirectAfter
}

// Router builds the HTTP handler with routing and middleware.
func (s *Server) Router() http.Handler {
	mux := http.NewServeMux()

	// Public endpoints.
	mux.HandleFunc("GET /healthz", s.handleHealth)
	mux.HandleFunc("POST /v1/auth/register", s.handleRegister)
	mux.HandleFunc("POST /v1/auth/login", s.handleLogin)
	mux.HandleFunc("GET /v1/auth/oidc/start", s.handleOIDCStart)
	mux.HandleFunc("GET /v1/auth/oidc/callback", s.handleOIDCCallback)

	// Authenticated endpoints, guarded by role-based permissions.
	mux.HandleFunc("GET /v1/auth/me", s.handleMe)

	mux.HandleFunc("GET /v1/findings", s.guard(auth.PermFindingsRead, s.handleListFindings))
	mux.HandleFunc("POST /v1/findings/ingest", s.guard(auth.PermFindingsWrite, s.handleIngestFindings))
	mux.HandleFunc("PATCH /v1/findings/{id}", s.guard(auth.PermFindingsWrite, s.handleUpdateFinding))
	mux.HandleFunc("GET /v1/summary", s.guard(auth.PermFindingsRead, s.handleSummary))

	mux.HandleFunc("GET /v1/assets", s.guard(auth.PermAssetsRead, s.handleListAssets))
	mux.HandleFunc("GET /v1/attack-path", s.guard(auth.PermAssetsRead, s.handleAttackPath))
	mux.HandleFunc("POST /v1/vulns/scan", s.guard(auth.PermScansRun, s.handleVulnScan))

	mux.HandleFunc("GET /v1/compliance/frameworks", s.guard(auth.PermComplianceRead, s.handleListFrameworks))
	mux.HandleFunc("GET /v1/compliance/frameworks/{id}/controls", s.guard(auth.PermComplianceRead, s.handleListControls))

	mux.HandleFunc("GET /v1/alerts", s.guard(auth.PermAlertsRead, s.handleListAlerts))
	mux.HandleFunc("POST /v1/alerts", s.guard(auth.PermAlertsWrite, s.handleCreateAlert))
	mux.HandleFunc("DELETE /v1/alerts/{id}", s.guard(auth.PermAlertsWrite, s.handleDeleteAlert))

	mux.HandleFunc("GET /v1/waf/rules", s.guard(auth.PermWAFRead, s.handleListWAFRules))
	mux.HandleFunc("POST /v1/waf/rules", s.guard(auth.PermWAFWrite, s.handleCreateWAFRule))
	mux.HandleFunc("DELETE /v1/waf/rules/{id}", s.guard(auth.PermWAFWrite, s.handleDeleteWAFRule))

	mux.HandleFunc("GET /v1/domains", s.guard(auth.PermDomainsRead, s.handleListDomains))
	mux.HandleFunc("POST /v1/domains", s.guard(auth.PermDomainsWrite, s.handleCreateDomain))
	mux.HandleFunc("GET /v1/domains/{id}/records", s.guard(auth.PermDomainsRead, s.handleListDNSRecords))
	mux.HandleFunc("POST /v1/domains/{id}/records", s.guard(auth.PermDomainsWrite, s.handleCreateDNSRecord))
	mux.HandleFunc("GET /v1/domains/{id}/subdomains", s.guard(auth.PermDomainsRead, s.handleListSubdomains))
	mux.HandleFunc("POST /v1/domains/{id}/enumerate", s.guard(auth.PermDomainsWrite, s.handleEnumerateSubdomains))
	mux.HandleFunc("POST /v1/domains/{id}/scan", s.guard(auth.PermDomainsWrite, s.handleScanDomain))

	return s.identity(s.logging(mux))
}

// context keys for identity resolved by the identity middleware.
type ctxKey int

const (
	tenantKey ctxKey = iota
	userKey
	roleKey
	authedKey
)

// identity middleware resolves the caller identity: a verified JWT when a
// secret is configured, or (dev mode) the X-Tenant-ID / X-User-Role headers.
func (s *Server) identity(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		if s.jwtSecret != "" {
			if claims, ok := bearerClaims(r, s.jwtSecret); ok {
				ctx = context.WithValue(ctx, userKey, claims.UserID)
				ctx = context.WithValue(ctx, tenantKey, claims.TenantID)
				ctx = context.WithValue(ctx, roleKey, claims.Role)
				ctx = context.WithValue(ctx, authedKey, true)
				next.ServeHTTP(w, r.WithContext(ctx))
				return
			}
			// No/invalid token: leave identity unset so public routes work and
			// guarded routes reject with 401.
			next.ServeHTTP(w, r.WithContext(ctx))
			return
		}

		// Dev mode (no JWT secret): derive identity from headers.
		role := r.Header.Get("X-User-Role")
		if !auth.IsValidRole(role) {
			role = auth.RoleOwner
		}
		var tenantID uuid.UUID
		if h := r.Header.Get("X-Tenant-ID"); h != "" {
			if id, perr := uuid.Parse(h); perr == nil {
				tenantID = id
			}
		}
		if tenantID == uuid.Nil {
			tenant, err := s.db.EnsureTenant(ctx, "default", "Default Tenant")
			if err != nil {
				s.writeError(w, http.StatusInternalServerError, err)
				return
			}
			tenantID = tenant.ID
		}
		ctx = context.WithValue(ctx, tenantKey, tenantID)
		ctx = context.WithValue(ctx, roleKey, role)
		ctx = context.WithValue(ctx, authedKey, true)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// bearerClaims extracts and validates a Bearer token from the request.
func bearerClaims(r *http.Request, secret string) (*auth.Claims, bool) {
	h := r.Header.Get("Authorization")
	if !strings.HasPrefix(h, "Bearer ") {
		return nil, false
	}
	claims, err := auth.ParseToken(secret, strings.TrimPrefix(h, "Bearer "))
	if err != nil {
		return nil, false
	}
	return claims, true
}

// guard wraps a handler, enforcing authentication and the given permission.
func (s *Server) guard(perm string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !authedFrom(r.Context()) {
			s.writeError(w, http.StatusUnauthorized, nil)
			return
		}
		if !auth.HasPermission(roleFrom(r.Context()), perm) {
			s.writeError(w, http.StatusForbidden, nil)
			return
		}
		next(w, r)
	}
}

// logging middleware emits an access log line per request.
func (s *Server) logging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		s.log.Info("api_request",
			"method", r.Method, "path", r.URL.Path, "duration", time.Since(start))
	})
}

// tenantFrom returns the tenant ID resolved by middleware.
func tenantFrom(ctx context.Context) uuid.UUID {
	id, _ := ctx.Value(tenantKey).(uuid.UUID)
	return id
}

// userFrom returns the authenticated user ID, or uuid.Nil if anonymous.
func userFrom(ctx context.Context) uuid.UUID {
	id, _ := ctx.Value(userKey).(uuid.UUID)
	return id
}

// roleFrom returns the caller role, defaulting to viewer.
func roleFrom(ctx context.Context) string {
	role, _ := ctx.Value(roleKey).(string)
	if role == "" {
		return auth.RoleViewer
	}
	return role
}

// authedFrom reports whether the caller presented valid credentials.
func authedFrom(ctx context.Context) bool {
	ok, _ := ctx.Value(authedKey).(bool)
	return ok
}

// audit records a platform action to the audit log.
func (s *Server) audit(ctx context.Context, action, resource string, metadata map[string]any) {
	actor := ""
	if u := userFrom(ctx); u != uuid.Nil {
		actor = u.String()
	}
	_ = s.db.CreateAuditLog(ctx, tenantFrom(ctx), actor, action, resource, metadata)
}

func (s *Server) writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func (s *Server) writeError(w http.ResponseWriter, status int, err error) {
	msg := http.StatusText(status)
	if err != nil {
		msg = err.Error()
	}
	s.writeJSON(w, status, map[string]string{"error": msg})
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	s.writeJSON(w, http.StatusOK, map[string]string{"status": "ok", "service": "castracloud-api"})
}

// parseBody decodes JSON into v.
func parseBody(r *http.Request, v any) error {
	return json.NewDecoder(r.Body).Decode(v)
}
