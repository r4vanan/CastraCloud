package api

import (
	"net/http"
	"time"

	"github.com/castracloud/castracloud/internal/auth"
	"github.com/castracloud/castracloud/internal/store"
	"github.com/google/uuid"
)

type registerRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	FullName string `json:"full_name"`
	Tenant   string `json:"tenant"` // tenant slug; defaults to "default"
}

// handleRegister creates the owner account for a new tenant. Adding users to
// an existing tenant must use an authenticated invitation or user-management
// flow rather than public self-registration.
func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	var req registerRequest
	if err := parseBody(r, &req); err != nil {
		s.writeError(w, http.StatusBadRequest, err)
		return
	}
	if req.Email == "" || req.Password == "" {
		s.writeError(w, http.StatusBadRequest, nil)
		return
	}

	slug := req.Tenant
	if slug == "" {
		slug = "default"
	}
	tenant, err := s.db.EnsureTenant(r.Context(), slug, slug)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, err)
		return
	}

	if _, err := s.db.GetUserByEmail(r.Context(), req.Email); err == nil {
		s.writeError(w, http.StatusConflict, nil)
		return
	}

	if n, err := s.db.CountUsers(r.Context(), tenant.ID); err != nil {
		s.writeError(w, http.StatusInternalServerError, err)
		return
	} else if n > 0 {
		s.writeError(w, http.StatusConflict, nil)
		return
	}
	role := auth.RoleOwner

	hash, err := auth.HashPassword(req.Password)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, err)
		return
	}

	user, err := s.db.CreateUserWithPassword(r.Context(), tenant.ID, req.Email, req.FullName, role, hash)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, err)
		return
	}
	_ = s.db.CreateAuditLog(r.Context(), tenant.ID, user.ID.String(), "auth.register", user.Email, map[string]any{"role": role})
	s.writeJSON(w, http.StatusCreated, user)
}

type loginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// handleLogin verifies credentials and issues a JWT.
func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if s.jwtSecret == "" {
		s.writeError(w, http.StatusServiceUnavailable, nil)
		return
	}
	var req loginRequest
	if err := parseBody(r, &req); err != nil {
		s.writeError(w, http.StatusBadRequest, err)
		return
	}

	user, err := s.db.GetUserByEmail(r.Context(), req.Email)
	if err == store.ErrNotFound {
		s.writeError(w, http.StatusUnauthorized, nil)
		return
	}
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, err)
		return
	}
	if !user.IsActive || !auth.CheckPassword(user.PasswordHash, req.Password) {
		s.writeError(w, http.StatusUnauthorized, nil)
		return
	}

	if user.MFAEnabled {
		mfaTok, exp, err := auth.IssueMFAToken(s.jwtSecret, 5*time.Minute, user.ID, user.TenantID)
		if err != nil {
			s.writeError(w, http.StatusInternalServerError, err)
			return
		}
		s.audit(r.Context(), "auth.login.mfa_challenge", user.Email, map[string]any{})
		s.writeJSON(w, http.StatusOK, map[string]any{
			"mfa_required": true,
			"mfa_token":    mfaTok,
			"expires_in":   int(time.Until(exp).Seconds()),
		})
		return
	}

	tok, exp, err := auth.IssueToken(s.jwtSecret, s.jwtTTL, user.ID, user.TenantID, user.Role)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, err)
		return
	}

	s.audit(r.Context(), "auth.login", user.Email, map[string]any{})
	s.writeJSON(w, http.StatusOK, map[string]any{
		"access_token": tok,
		"token_type":   "bearer",
		"expires_in":   int(time.Until(exp).Seconds()),
		"user":         user,
	})
}

// handleMe returns the authenticated user's profile.
func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	userID := userFrom(r.Context())
	if userID == uuid.Nil {
		s.writeError(w, http.StatusUnauthorized, nil)
		return
	}
	user, err := s.db.GetUserByID(r.Context(), userID)
	if err == store.ErrNotFound {
		s.writeError(w, http.StatusUnauthorized, nil)
		return
	}
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, err)
		return
	}
	s.writeJSON(w, http.StatusOK, user)
}
