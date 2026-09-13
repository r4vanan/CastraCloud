package crypto

import (
	"bytes"
	"testing"
)

func TestEncryptDecryptRoundtrip(t *testing.T) {
	key, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	secret := `{"access_key":"AKIA...","secret_key":"..."}`
	ct, err := Encrypt(key, secret)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if bytes.Contains(ct, []byte("AKIA")) {
		t.Fatal("ciphertext must not contain plaintext")
	}

	got, err := Decrypt(key, ct)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if got != secret {
		t.Fatalf("Decrypt = %q, want %q", got, secret)
	}
}

func TestEncryptUsesFreshNonce(t *testing.T) {
	key, _ := GenerateKey()
	a, _ := Encrypt(key, "same")
	b, _ := Encrypt(key, "same")
	if bytes.Equal(a, b) {
		t.Fatal("two encryptions of the same plaintext must differ (random nonce)")
	}
}

func TestDecryptRejectsWrongKey(t *testing.T) {
	k1, _ := GenerateKey()
	k2, _ := GenerateKey()
	ct, _ := Encrypt(k1, "secret")
	if _, err := Decrypt(k2, ct); err == nil {
		t.Fatal("expected error when decrypting with the wrong key")
	}
}

func TestEncryptRejectsInvalidKey(t *testing.T) {
	if _, err := Encrypt("not-base64!", "secret"); err == nil {
		t.Fatal("expected error for invalid key")
	}
	if _, err := Encrypt("c2hvcnQ=", "secret"); err == nil { // base64 but wrong length
		t.Fatal("expected error for wrong-length key")
	}
}
