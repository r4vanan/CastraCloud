package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"
)

const (
	totpPeriod = 30
	totpDigits = 6
)

// GenerateTOTPSecret returns a random Base32 TOTP secret.
func GenerateTOTPSecret() (string, error) {
	raw := make([]byte, 20)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(raw), nil
}

// TOTPURI returns the authenticator-app enrollment URI for an account.
func TOTPURI(issuer, account, secret string) string {
	label := url.QueryEscape(issuer + ":" + account)
	q := url.Values{}
	q.Set("secret", secret)
	q.Set("issuer", issuer)
	q.Set("algorithm", "SHA1")
	q.Set("digits", fmt.Sprint(totpDigits))
	q.Set("period", fmt.Sprint(totpPeriod))
	return "otpauth://totp/" + label + "?" + q.Encode()
}

// VerifyTOTP validates a six-digit TOTP code, allowing one adjacent time step
// for normal clock skew.
func VerifyTOTP(secret, code string, now time.Time) bool {
	code = strings.TrimSpace(code)
	if len(code) != totpDigits {
		return false
	}
	for _, r := range code {
		if r < '0' || r > '9' {
			return false
		}
	}
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(strings.TrimSpace(secret)))
	if err != nil {
		return false
	}
	step := now.Unix() / totpPeriod
	for offset := int64(-1); offset <= 1; offset++ {
		if hmac.Equal([]byte(totpCode(key, uint64(step+offset))), []byte(code)) {
			return true
		}
	}
	return false
}

func totpCode(key []byte, counter uint64) string {
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, counter)
	mac := hmac.New(sha1.New, key)
	_, _ = mac.Write(buf)
	sum := mac.Sum(nil)
	offset := int(sum[len(sum)-1] & 0x0f)
	value := binary.BigEndian.Uint32(sum[offset:offset+4]) & 0x7fffffff
	return fmt.Sprintf("%06d", value%1_000_000)
}

// GenerateRecoveryCodes creates single-use recovery codes for MFA recovery.
func GenerateRecoveryCodes(count int) ([]string, error) {
	if count < 1 {
		return nil, errors.New("recovery code count must be positive")
	}
	codes := make([]string, 0, count)
	for i := 0; i < count; i++ {
		raw := make([]byte, 8)
		if _, err := rand.Read(raw); err != nil {
			return nil, err
		}
		v := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(raw)
		codes = append(codes, v[:4]+"-"+v[4:8])
	}
	return codes, nil
}

// HashSecret derives a fixed-size hash for reset and recovery tokens.
func HashSecret(raw string) []byte {
	sum := sha256.Sum256([]byte(strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(raw), "-", ""))))
	return sum[:]
}

// GenerateResetToken produces a URL-safe password-reset token.
func GenerateResetToken() (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}
