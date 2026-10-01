package api

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/castracloud/castracloud/internal/auth"
	"github.com/castracloud/castracloud/internal/config"
	credentialcrypto "github.com/castracloud/castracloud/internal/crypto"
	"github.com/google/uuid"
)

const mfaRecoveryCodeCount = 10

// mfaEncrypt encrypts a plaintext MFA secret with the platform key.
func (s *Server) mfaEncrypt(plain string) ([]byte, error) {
	key := config.Env("CREDENTIAL_ENCRYPTION_KEY", "")
	if key == "" {
		return nil, errors.New("CREDENTIAL_ENCRYPTION_KEY is not set")
	}
	return credentialcrypto.Encrypt(key, plain)
}

// mfaDecrypt decrypts an encrypted MFA secret.
func (s *Server) mfaDecrypt(ct []byte) (string, error) {
	key := config.Env("CREDENTIAL_ENCRYPTION_KEY", "")
	if key == "" {
		return "", errors.New("CREDENTIAL_ENCRYPTION_KEY is not set")
	}
	return credentialcrypto.Decrypt(key, ct)
}

// mfaUser fetches the authenticated user or rejects the request.
func (s *Server) mfaUser(w http.ResponseWriter, r *http.Request) (uuid.UUID, string, bool) {
	userID := userFrom(r.Context())
	if userID == uuid.Nil {
		s.writeError(w, http.StatusUnauthorized, nil)
		return uuid.Nil, "", false
	}
	user, err := s.db.GetUserByID(r.Context(), userID)
	if err != nil {
		s.writeError(w, http.StatusUnauthorized, nil)
		return uuid.Nil, "", false
	}
	return user.ID, user.Email, true
}

// handleMFAStatus reports whether MFA is enabled or pending enrollment.
func (s *Server) handleMFAStatus(w http.ResponseWriter, r *http.Request) {
	userID, _, ok := s.mfaUser(w, r)
	if !ok {
		return
	}
	user, err := s.db.GetUserByID(r.Context(), userID)
	if err != nil {
		s.writeError(w, http.StatusUnauthorized, nil)
		return
	}
	pending := false
	if secret, err := s.db.GetMFAPendingSecret(r.Context(), userID); err == nil && len(secret) > 0 {
		pending = true
	}
	s.writeJSON(w, http.StatusOK, map[string]any{"enabled": user.MFAEnabled, "pending": pending})
}

// handleMFAEnroll begins TOTP enrollment, returning the secret and otpauth URI.
func (s *Server) handleMFAEnroll(w http.ResponseWriter, r *http.Request) {
	userID, email, ok := s.mfaUser(w, r)
	if !ok {
		return
	}
	user, err := s.db.GetUserByID(r.Context(), userID)
	if err != nil {
		s.writeError(w, http.StatusUnauthorized, nil)
		return
	}
	if user.MFAEnabled {
		s.writeError(w, http.StatusConflict, nil)
		return
	}

	secret, err := auth.GenerateTOTPSecret()
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, err)
		return
	}
	encrypted, err := s.mfaEncrypt(secret)
	if err != nil {
		s.writeError(w, http.StatusServiceUnavailable, err)
		return
	}
	if err := s.db.SetMFAPendingSecret(r.Context(), userID, encrypted); err != nil {
		s.writeError(w, http.StatusInternalServerError, err)
		return
	}

	s.audit(r.Context(), "auth.mfa.enroll", email, map[string]any{})
	s.writeJSON(w, http.StatusOK, map[string]string{
		"secret":      secret,
		"otpauth_uri": auth.TOTPURI("CastraCloud", email, secret),
	})
}

// handleMFAVerify confirms the pending TOTP secret and returns recovery codes.
func (s *Server) handleMFAVerify(w http.ResponseWriter, r *http.Request) {
	userID, email, ok := s.mfaUser(w, r)
	if !ok {
		return
	}
	var body struct {
		Code string `json:"code"`
	}
	if err := parseBody(r, &body); err != nil {
		s.writeError(w, http.StatusBadRequest, err)
		return
	}

	encrypted, err := s.db.GetMFAPendingSecret(r.Context(), userID)
	if err != nil || len(encrypted) == 0 {
		s.writeError(w, http.StatusBadRequest, nil)
		return
	}
	secret, err := s.mfaDecrypt(encrypted)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, err)
		return
	}
	if !auth.VerifyTOTP(secret, body.Code, time.Now()) {
		s.writeError(w, http.StatusUnauthorized, nil)
		return
	}

	if err := s.db.EnableMFA(r.Context(), userID, encrypted); err != nil {
		s.writeError(w, http.StatusInternalServerError, err)
		return
	}
	codes, err := s.generateRecoveryCodes(r.Context(), userID)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, err)
		return
	}

	s.audit(r.Context(), "auth.mfa.enabled", email, map[string]any{})
	s.writeJSON(w, http.StatusOK, map[string]any{"recovery_codes": codes})
}

// handleMFADisable turns MFA off for the authenticated user.
func (s *Server) handleMFADisable(w http.ResponseWriter, r *http.Request) {
	userID, email, ok := s.mfaUser(w, r)
	if !ok {
		return
	}
	if err := s.db.DisableMFA(r.Context(), userID); err != nil {
		s.writeError(w, http.StatusInternalServerError, err)
		return
	}
	s.audit(r.Context(), "auth.mfa.disabled", email, map[string]any{})
	s.writeJSON(w, http.StatusOK, map[string]bool{"enabled": false})
}

// handleMFARegenerateCodes issues a fresh recovery-code set for MFA users.
func (s *Server) handleMFARegenerateCodes(w http.ResponseWriter, r *http.Request) {
	userID, email, ok := s.mfaUser(w, r)
	if !ok {
		return
	}
	user, err := s.db.GetUserByID(r.Context(), userID)
	if err != nil || !user.MFAEnabled {
		s.writeError(w, http.StatusBadRequest, nil)
		return
	}
	codes, err := s.generateRecoveryCodes(r.Context(), userID)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, err)
		return
	}
	s.audit(r.Context(), "auth.mfa.recovery_codes", email, map[string]any{})
	s.writeJSON(w, http.StatusOK, map[string]any{"recovery_codes": codes})
}

// generateRecoveryCodes creates, stores, and returns new recovery codes.
func (s *Server) generateRecoveryCodes(ctx context.Context, userID uuid.UUID) ([]string, error) {
	codes, err := auth.GenerateRecoveryCodes(mfaRecoveryCodeCount)
	if err != nil {
		return nil, err
	}
	hashes := make([][]byte, 0, len(codes))
	for _, c := range codes {
		hashes = append(hashes, auth.HashSecret(c))
	}
	if err := s.db.ReplaceRecoveryCodes(ctx, userID, hashes); err != nil {
		return nil, err
	}
	return codes, nil
}

// handleMFAVerifyLogin completes the second factor and issues a full session.
func (s *Server) handleMFAVerifyLogin(w http.ResponseWriter, r *http.Request) {
	if s.jwtSecret == "" {
		s.writeError(w, http.StatusServiceUnavailable, nil)
		return
	}
	var body struct {
		MFAToken     string `json:"mfa_token"`
		Code         string `json:"code"`
		RecoveryCode string `json:"recovery_code"`
	}
	if err := parseBody(r, &body); err != nil {
		s.writeError(w, http.StatusBadRequest, err)
		return
	}
	if body.MFAToken == "" {
		s.writeError(w, http.StatusBadRequest, nil)
		return
	}

	claims, err := auth.ParseToken(s.jwtSecret, body.MFAToken)
	if err != nil || claims.Purpose != auth.PurposeMFA {
		s.writeError(w, http.StatusUnauthorized, nil)
		return
	}

	user, err := s.db.GetUserByID(r.Context(), claims.UserID)
	if err != nil || !user.IsActive || !user.MFAEnabled {
		s.writeError(w, http.StatusUnauthorized, nil)
		return
	}

	verified := false
	if body.Code != "" {
		encrypted, err := s.db.GetMFASecret(r.Context(), user.ID)
		if err != nil {
			s.writeError(w, http.StatusInternalServerError, err)
			return
		}
		secret, err := s.mfaDecrypt(encrypted)
		if err != nil {
			s.writeError(w, http.StatusInternalServerError, err)
			return
		}
		verified = auth.VerifyTOTP(secret, body.Code, time.Now())
	} else if body.RecoveryCode != "" {
		ok, err := s.db.ConsumeRecoveryCode(r.Context(), user.ID, auth.HashSecret(body.RecoveryCode))
		if err != nil {
			s.writeError(w, http.StatusInternalServerError, err)
			return
		}
		verified = ok
	}
	if !verified {
		s.writeError(w, http.StatusUnauthorized, nil)
		return
	}

	tok, exp, err := auth.IssueToken(s.jwtSecret, s.jwtTTL, user.ID, user.TenantID, user.Role)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, err)
		return
	}

	s.db.CreateAuditLog(r.Context(), user.TenantID, user.ID.String(), "auth.login", user.Email, map[string]any{"mfa": true})
	s.writeJSON(w, http.StatusOK, map[string]any{
		"access_token": tok,
		"token_type":   "bearer",
		"expires_in":   int(time.Until(exp).Seconds()),
		"user":         user,
	})
}
