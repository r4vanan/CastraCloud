package api

import (
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"sync"
	"time"

	"github.com/castracloud/castracloud/internal/auth"
	"github.com/castracloud/castracloud/internal/store"
)

// oidcSession holds transient state for an in-flight OIDC authorization.
type oidcSession struct {
	verifier string
	nonce    string
	expires  time.Time
}

// oidcSessionStore is an in-memory store for OIDC authorization state.
type oidcSessionStore struct {
	mu sync.Mutex
	m  map[string]oidcSession
}

func newOIDCSessionStore() *oidcSessionStore {
	return &oidcSessionStore{m: map[string]oidcSession{}}
}

func (s *oidcSessionStore) put(state string, sess oidcSession) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.m[state] = sess
}

func (s *oidcSessionStore) take(state string) (oidcSession, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.m[state]
	if !ok {
		return oidcSession{}, false
	}
	delete(s.m, state)
	if time.Now().After(sess.expires) {
		return oidcSession{}, false
	}
	return sess, true
}

func randomString(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// handleOIDCStart initiates the OIDC authorization-code flow.
func (s *Server) handleOIDCStart(w http.ResponseWriter, r *http.Request) {
	if s.oidc == nil {
		s.writeError(w, http.StatusNotFound, nil)
		return
	}
	state := randomString(32)
	nonce := randomString(32)
	pkce := auth.NewPKCE()

	s.oidcSessions.put(state, oidcSession{
		verifier: pkce.Verifier,
		nonce:    nonce,
		expires:  time.Now().Add(10 * time.Minute),
	})

	http.Redirect(w, r, s.oidc.AuthURL(state, nonce, pkce), http.StatusFound)
}

// handleOIDCCallback redeems the authorization code and completes login.
func (s *Server) handleOIDCCallback(w http.ResponseWriter, r *http.Request) {
	if s.oidc == nil {
		s.writeError(w, http.StatusNotFound, nil)
		return
	}
	q := r.URL.Query()
	code, state := q.Get("code"), q.Get("state")
	if code == "" || state == "" {
		s.writeError(w, http.StatusBadRequest, nil)
		return
	}

	sess, ok := s.oidcSessions.take(state)
	if !ok {
		s.writeError(w, http.StatusBadRequest, nil)
		return
	}

	id, err := s.oidc.Exchange(r.Context(), code, sess.verifier, sess.nonce)
	if err != nil {
		s.writeError(w, http.StatusUnauthorized, err)
		return
	}

	user, err := s.provisionOIDCUser(r, id)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, err)
		return
	}

	tok, exp, err := auth.IssueToken(s.jwtSecret, s.jwtTTL, user.ID, user.TenantID, user.Role)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, err)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "castra_token",
		Value:    tok,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Expires:  exp,
		MaxAge:   int(time.Until(exp).Seconds()),
	})

	s.audit(r.Context(), "auth.oidc_login", user.Email, map[string]any{"sub": id.Sub})
	http.Redirect(w, r, s.oidcRedirectAfter, http.StatusFound)
}

// provisionOIDCUser finds or creates the local user for a verified identity.
func (s *Server) provisionOIDCUser(r *http.Request, id *auth.OIDCIdentity) (*store.User, error) {
	slug := s.oidcTenantSlug
	if slug == "" {
		slug = "default"
	}
	tenant, err := s.db.EnsureTenant(r.Context(), slug, slug)
	if err != nil {
		return nil, err
	}

	user, err := s.db.GetUserByEmail(r.Context(), id.Email)
	if err == store.ErrNotFound {
		role := auth.RoleViewer
		if n, cerr := s.db.CountUsers(r.Context(), tenant.ID); cerr == nil && n == 0 {
			role = auth.RoleOwner
		}
		return s.db.CreateUserWithPassword(r.Context(), tenant.ID, id.Email, id.Name, role, "")
	}
	if err != nil {
		return nil, err
	}
	if !user.IsActive {
		return nil, store.ErrNotFound
	}
	return user, nil
}
