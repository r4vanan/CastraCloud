package auth

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestPasswordHashRoundtrip(t *testing.T) {
	hash, err := HashPassword("s3cret-p@ss")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if hash == "s3cret-p@ss" {
		t.Fatal("hash should not equal plaintext")
	}
	if !CheckPassword(hash, "s3cret-p@ss") {
		t.Fatal("CheckPassword should accept the correct password")
	}
	if CheckPassword(hash, "wrong") {
		t.Fatal("CheckPassword should reject an incorrect password")
	}
}

func TestHashPasswordRejectsEmpty(t *testing.T) {
	if _, err := HashPassword(""); err == nil {
		t.Fatal("expected error for empty password")
	}
}

func TestJWTIssueAndParse(t *testing.T) {
	secret := "test-secret"
	userID := uuid.New()
	tenantID := uuid.New()

	tok, exp, err := IssueToken(secret, time.Hour, userID, tenantID, RoleAnalyst)
	if err != nil {
		t.Fatalf("IssueToken: %v", err)
	}
	if !exp.After(time.Now()) {
		t.Fatal("expiry should be in the future")
	}

	claims, err := ParseToken(secret, tok)
	if err != nil {
		t.Fatalf("ParseToken: %v", err)
	}
	if claims.UserID != userID {
		t.Fatalf("UserID = %v, want %v", claims.UserID, userID)
	}
	if claims.TenantID != tenantID {
		t.Fatalf("TenantID = %v, want %v", claims.TenantID, tenantID)
	}
	if claims.Role != RoleAnalyst {
		t.Fatalf("Role = %q, want %q", claims.Role, RoleAnalyst)
	}
}

func TestParseTokenRejectsBadSecret(t *testing.T) {
	tok, _, err := IssueToken("good-secret", time.Hour, uuid.New(), uuid.New(), RoleViewer)
	if err != nil {
		t.Fatalf("IssueToken: %v", err)
	}
	if _, err := ParseToken("bad-secret", tok); err == nil {
		t.Fatal("expected error for wrong secret")
	}
}

func TestRBAC(t *testing.T) {
	cases := []struct {
		role string
		perm string
		want bool
	}{
		{RoleOwner, PermUsersManage, true},
		{RoleAdmin, PermUsersManage, false}, // admin cannot manage users
		{RoleAdmin, PermConnectorsWrite, true},
		{RoleAnalyst, PermFindingsWrite, true},
		{RoleAnalyst, PermConnectorsWrite, false},
		{RoleViewer, PermFindingsRead, true},
		{RoleViewer, PermFindingsWrite, false},
		{"bogus", PermFindingsRead, false},
	}
	for _, c := range cases {
		if got := HasPermission(c.role, c.perm); got != c.want {
			t.Errorf("HasPermission(%q, %q) = %v, want %v", c.role, c.perm, got, c.want)
		}
	}
}

func TestIsValidRole(t *testing.T) {
	for _, r := range []string{RoleOwner, RoleAdmin, RoleAnalyst, RoleViewer} {
		if !IsValidRole(r) {
			t.Errorf("IsValidRole(%q) = false, want true", r)
		}
	}
	if IsValidRole("superuser") {
		t.Error("IsValidRole(superuser) = true, want false")
	}
}
