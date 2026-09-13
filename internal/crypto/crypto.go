// Package crypto encrypts cloud-connector credentials at rest using
// AES-256-GCM. The key is supplied via CREDENTIAL_ENCRYPTION_KEY (base64) so
// secrets are never stored in plaintext. In production this key should come
// from a secret manager (Vault / sealed secrets) rather than a plain env var.
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
)

// KeyBytes is the required raw key length for AES-256.
const KeyBytes = 32

// GenerateKey returns a new random base64-encoded 256-bit key.
func GenerateKey() (string, error) {
	raw := make([]byte, KeyBytes)
	if _, err := io.ReadFull(rand.Reader, raw); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(raw), nil
}

// Encrypt encrypts plaintext with AES-256-GCM using the given base64 key,
// returning nonce-prefixed ciphertext suitable for a BYTEA column.
func Encrypt(key, plaintext string) ([]byte, error) {
	aead, err := newAEAD(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return aead.Seal(nonce, nonce, []byte(plaintext), nil), nil
}

// Decrypt reverses Encrypt.
func Decrypt(key string, ciphertext []byte) (string, error) {
	aead, err := newAEAD(key)
	if err != nil {
		return "", err
	}
	if len(ciphertext) < aead.NonceSize() {
		return "", errors.New("ciphertext too short")
	}
	nonce, ct := ciphertext[:aead.NonceSize()], ciphertext[aead.NonceSize():]
	pt, err := aead.Open(nil, nonce, ct, nil)
	if err != nil {
		return "", err
	}
	return string(pt), nil
}

func newAEAD(key string) (cipher.AEAD, error) {
	raw, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		return nil, errors.New("credential key is not valid base64")
	}
	if len(raw) != KeyBytes {
		return nil, errors.New("credential key must decode to 32 bytes")
	}
	block, err := aes.NewCipher(raw)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}
