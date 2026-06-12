package config

import (
	"strings"
	"testing"
)

// TestValidateSecurity_rejectsDemoSecrets proves the production validator no
// longer waves through the repo-committed placeholder secrets (the SEC1 gap:
// they differ from the original defaults, so exact-match checks passed).
func TestValidateSecurity_rejectsDemoSecrets(t *testing.T) {
	t.Setenv("APP_ENV", "production")
	// A real, strong baseline so we isolate the one weak value under test.
	strong := strings.Repeat("S7r0ng-Pr0d-Secret!", 3) // >=32 bytes, no markers
	base := map[string]string{
		"JWT_SECRET":               strong,
		"BOOTSTRAP_ADMIN_PASSWORD": "a-real-strong-admin-pw",
		"INTERNAL_SERVICE_TOKEN":   "a-real-strong-internal-token",
		"AUTH_DATABASE_URL":        "postgres://iam_app:realpw@db:5432/auth_db",
	}

	cases := []struct {
		name, key, val string
	}{
		{"demo jwt", "JWT_SECRET", "k8s-demo-jwt-secret-rotate-me-min-32-bytes"},
		{"demo admin", "BOOTSTRAP_ADMIN_PASSWORD", "ChangeMeAdmin-2026"},
		{"old admin default", "BOOTSTRAP_ADMIN_PASSWORD", "admin12345"},
		{"demo internal token", "INTERNAL_SERVICE_TOKEN", "k8s-demo-internal-token-rotate-me"},
		{"dev internal token", "INTERNAL_SERVICE_TOKEN", "dev-internal-token-change-me"},
		{"placeholder db password", "AUTH_DATABASE_URL", "postgres://app:app_secret@db:5432/auth_db"},
		{"old jwt default", "JWT_SECRET", DefaultJWTSecret},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for k, v := range base {
				t.Setenv(k, v)
			}
			t.Setenv(tc.key, tc.val)
			if err := ValidateSecurity(); err == nil {
				t.Fatalf("expected ValidateSecurity to reject %s=%q, got nil", tc.key, tc.val)
			}
		})
	}
}

// TestValidateSecurity_passesStrongSecrets confirms real values are accepted.
func TestValidateSecurity_passesStrongSecrets(t *testing.T) {
	t.Setenv("APP_ENV", "production")
	t.Setenv("JWT_SECRET", strings.Repeat("S7r0ng-Pr0d-Secret!", 3))
	t.Setenv("BOOTSTRAP_ADMIN_PASSWORD", "a-real-strong-admin-pw")
	t.Setenv("INTERNAL_SERVICE_TOKEN", "a-real-strong-internal-token")
	t.Setenv("AUTH_DATABASE_URL", "postgres://iam_app:realpw@db:5432/auth_db")
	if err := ValidateSecurity(); err != nil {
		t.Fatalf("strong config should pass, got %v", err)
	}
}

// TestValidateSecurity_skippedOutsideProd confirms dev is unaffected.
func TestValidateSecurity_skippedOutsideProd(t *testing.T) {
	t.Setenv("APP_ENV", "development")
	t.Setenv("JWT_SECRET", "admin12345") // weak, but not production
	if err := ValidateSecurity(); err != nil {
		t.Fatalf("validation must be a no-op outside production, got %v", err)
	}
}
