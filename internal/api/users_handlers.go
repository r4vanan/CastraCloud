package api

import (
	"crypto/rand"
	"net/http"

	"github.com/castracloud/castracloud/internal/auth"
	"github.com/castracloud/castracloud/internal/store"
	"github.com/google/uuid"
)

// handleListUsers returns the users in the caller's tenant (owner only).
func (s *Server) handleListUsers(w http.ResponseWriter, r *http.Request) {
	tenant := tenantFrom(r.Context())
	users, err := s.db.ListUsers(r.Context(), tenant)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, err)
		return
	}
	s.writeJSON(w, http.StatusOK, users)
}

// handleCreateUser provisions a new user in the tenant. When no password is
// supplied, a temporary one is generated and returned once.
func (s *Server) handleCreateUser(w http.ResponseWriter, r *http.Request) {
	tenant := tenantFrom(r.Context())
	var body struct {
		Email    string `json:"email"`
		FullName string `json:"full_name"`
		Role     string `json:"role"`
		Password string `json:"password"`
	}
	if err := parseBody(r, &body); err != nil {
		s.writeError(w, http.StatusBadRequest, err)
		return
	}
	if body.Email == "" {
		s.writeError(w, http.StatusBadRequest, nil)
		return
	}
	if body.Role == "" {
		body.Role = auth.RoleViewer
	}
	if !auth.IsValidRole(body.Role) {
		s.writeError(w, http.StatusBadRequest, nil)
		return
	}

	if _, err := s.db.GetUserByEmail(r.Context(), body.Email); err == nil {
		s.writeError(w, http.StatusConflict, nil)
		return
	}

	tempPassword := ""
	if body.Password == "" {
		generated, err := generateTempPassword()
		if err != nil {
			s.writeError(w, http.StatusInternalServerError, err)
			return
		}
		tempPassword = generated
		body.Password = generated
	}
	hash, err := auth.HashPassword(body.Password)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, err)
		return
	}

	user, err := s.db.CreateUserWithPassword(r.Context(), tenant, body.Email, body.FullName, body.Role, hash)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, err)
		return
	}

	s.audit(r.Context(), "user.create", user.Email, map[string]any{"role": user.Role})
	resp := map[string]any{"user": user}
	if tempPassword != "" {
		resp["temp_password"] = tempPassword
	}
	s.writeJSON(w, http.StatusCreated, resp)
}

// handleUpdateUser updates a user's role and/or active status.
func (s *Server) handleUpdateUser(w http.ResponseWriter, r *http.Request) {
	tenant := tenantFrom(r.Context())
	caller := userFrom(r.Context())
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		s.writeError(w, http.StatusBadRequest, err)
		return
	}
	if id == caller {
		s.writeError(w, http.StatusBadRequest, nil)
		return
	}

	var body struct {
		Role     *string `json:"role"`
		IsActive *bool   `json:"is_active"`
	}
	if err := parseBody(r, &body); err != nil {
		s.writeError(w, http.StatusBadRequest, err)
		return
	}
	if body.Role != nil && !auth.IsValidRole(*body.Role) {
		s.writeError(w, http.StatusBadRequest, nil)
		return
	}

	user, err := s.db.UpdateUser(r.Context(), tenant, id, body.Role, body.IsActive)
	if err != nil {
		if err == store.ErrNotFound {
			s.writeError(w, http.StatusNotFound, nil)
			return
		}
		s.writeError(w, http.StatusInternalServerError, err)
		return
	}

	s.audit(r.Context(), "user.update", user.Email, map[string]any{"role": user.Role, "is_active": user.IsActive})
	s.writeJSON(w, http.StatusOK, user)
}

// handleDeleteUser deactivates a user (soft delete).
func (s *Server) handleDeleteUser(w http.ResponseWriter, r *http.Request) {
	tenant := tenantFrom(r.Context())
	caller := userFrom(r.Context())
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		s.writeError(w, http.StatusBadRequest, err)
		return
	}
	if id == caller {
		s.writeError(w, http.StatusBadRequest, nil)
		return
	}

	user, err := s.db.GetUserByID(r.Context(), id)
	if err != nil {
		s.writeError(w, http.StatusNotFound, nil)
		return
	}

	if err := s.db.DeactivateUser(r.Context(), tenant, id); err != nil {
		if err == store.ErrNotFound {
			s.writeError(w, http.StatusNotFound, nil)
			return
		}
		s.writeError(w, http.StatusInternalServerError, err)
		return
	}

	s.audit(r.Context(), "user.deactivate", user.Email, map[string]any{})
	s.writeJSON(w, http.StatusOK, map[string]bool{"deactivated": true})
}

// generateTempPassword returns a random password satisfying the policy.
func generateTempPassword() (string, error) {
	const set = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	for i := range b {
		b[i] = set[int(b[i])%len(set)]
	}
	// Guarantee at least one upper, one lower, and one digit.
	b[0] = 'A'
	b[1] = 'a'
	b[2] = '0'
	return string(b), nil
}
