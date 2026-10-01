package api

import (
	"net/http"
	"time"

	"github.com/castracloud/castracloud/internal/auth"
	"github.com/castracloud/castracloud/internal/store"
)

// handleRequestPasswordReset issues a single-use password-reset token for a
// local account. Because there is no mail transport, the token is returned in
// the response (and logged) — in a production deployment this would be emailed.
func (s *Server) handleRequestPasswordReset(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Email string `json:"email"`
	}
	if err := parseBody(r, &body); err != nil {
		s.writeError(w, http.StatusBadRequest, err)
		return
	}

	user, err := s.db.GetUserByEmail(r.Context(), body.Email)
	if err == store.ErrNotFound {
		// Do not reveal whether the account exists.
		s.writeJSON(w, http.StatusOK, map[string]string{
			"message": "If an account exists for that email, a reset link has been sent.",
		})
		return
	}
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, err)
		return
	}

	raw, err := auth.GenerateResetToken()
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, err)
		return
	}
	if err := s.db.CreatePasswordResetToken(r.Context(), user.ID, auth.HashSecret(raw), time.Now().Add(time.Hour)); err != nil {
		s.writeError(w, http.StatusInternalServerError, err)
		return
	}

	s.log.Info("password reset requested", "email", user.Email, "token", raw)
	s.writeJSON(w, http.StatusOK, map[string]string{
		"message":     "Use the token below to reset your password.",
		"reset_token": raw,
	})
}

// handleConfirmPasswordReset validates a reset token and applies a new password.
func (s *Server) handleConfirmPasswordReset(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Token    string `json:"token"`
		Password string `json:"password"`
	}
	if err := parseBody(r, &body); err != nil {
		s.writeError(w, http.StatusBadRequest, err)
		return
	}
	if body.Token == "" || body.Password == "" {
		s.writeError(w, http.StatusBadRequest, nil)
		return
	}

	hash := auth.HashSecret(body.Token)
	tok, err := s.db.GetPasswordResetToken(r.Context(), hash)
	if err == store.ErrNotFound {
		s.writeError(w, http.StatusBadRequest, nil)
		return
	}
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, err)
		return
	}
	if tok.UsedAt != nil {
		s.writeError(w, http.StatusBadRequest, nil)
		return
	}
	if time.Now().After(tok.ExpiresAt) {
		s.writeError(w, http.StatusBadRequest, nil)
		return
	}

	pwHash, err := auth.HashPassword(body.Password)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, err)
		return
	}
	if err := s.db.UpdateUserPassword(r.Context(), tok.UserID, pwHash); err != nil {
		s.writeError(w, http.StatusInternalServerError, err)
		return
	}
	if err := s.db.ConsumePasswordResetToken(r.Context(), hash); err != nil {
		s.writeError(w, http.StatusInternalServerError, err)
		return
	}

	s.writeJSON(w, http.StatusOK, map[string]string{"status": "password updated"})
}
