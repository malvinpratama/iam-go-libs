// Package config loads service configuration from environment variables.
package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// DefaultJWTSecret is the placeholder secret that MUST NOT be used in production.
const DefaultJWTSecret = "change-me-in-production-please-32bytes-min"

// IsProduction reports whether APP_ENV indicates a production deployment.
func IsProduction() bool {
	switch os.Getenv("APP_ENV") {
	case "production", "prod":
		return true
	}
	return false
}

// InternalToken is the shared secret the gateway presents to internal services
// (defense-in-depth). Empty means enforcement is disabled (local dev).
func InternalToken() string { return os.Getenv("INTERNAL_SERVICE_TOKEN") }

// NatsURL is the NATS JetStream connection string for async inter-service
// events. Empty disables the event publisher/consumer (the gateway's lazy
// profile healing remains as a fallback), keeping the broker optional.
func NatsURL() string { return os.Getenv("NATS_URL") }

// OTLPEndpoint is the OpenTelemetry collector endpoint (host:port, gRPC) for
// trace export. Empty disables tracing, keeping observability optional.
func OTLPEndpoint() string { return os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT") }

// MetricsAddr is the listen address for the Prometheus /metrics endpoint.
func MetricsAddr() string { return ":" + Getenv("METRICS_PORT", "9100") }

// ── v0.2 Security+ feature toggles (all default to non-breaking) ─────

// RequireEmailVerification blocks login for unverified users when true.
func RequireEmailVerification() bool { return os.Getenv("REQUIRE_EMAIL_VERIFICATION") == "true" }

// LoginMaxFailures is the failed-login threshold before lockout (0 disables).
func LoginMaxFailures() int { return GetenvInt("LOGIN_MAX_FAILURES", 5) }

// LockoutDuration is how long an account stays locked after too many failures.
func LockoutDuration() time.Duration { return GetenvDuration("LOGIN_LOCKOUT_SECONDS", 900) }

// AuditEnabled controls whether sensitive actions are written to the audit log.
func AuditEnabled() bool { return Getenv("AUDIT_ENABLED", "true") != "false" }

// weakSecretMarkers are substrings that betray a placeholder/demo/dev secret.
// The committed demo values (k8s-demo-…-rotate-me, app_secret, dev-…-change-me,
// ChangeMeAdmin-…) all contain one, so exact-matching the old defaults was not
// enough — these markers reject every shipped placeholder.
var weakSecretMarkers = []string{
	"change-me", "changeme", "rotate-me", "k8s-demo", "demo-secret",
	"dev-internal", "admin12345", "app_secret", "console-demo",
}

// looksWeak reports whether s contains a known placeholder marker.
func looksWeak(s string) bool {
	l := strings.ToLower(s)
	for _, m := range weakSecretMarkers {
		if strings.Contains(l, m) {
			return true
		}
	}
	return false
}

// ValidateSecurity fails fast on insecure configuration in production. It rejects
// not just the original defaults but any value carrying a placeholder marker, so
// a repo-committed demo secret cannot boot a production deployment.
func ValidateSecurity() error {
	if !IsProduction() {
		return nil
	}
	if s := Getenv("JWT_SECRET", DefaultJWTSecret); len(s) < 32 || looksWeak(s) {
		return fmt.Errorf("JWT_SECRET must be a strong, non-placeholder value (>=32 bytes) in production")
	}
	if p := os.Getenv("BOOTSTRAP_ADMIN_PASSWORD"); p == "" || looksWeak(p) {
		return fmt.Errorf("BOOTSTRAP_ADMIN_PASSWORD must be set to a strong, non-placeholder value in production")
	}
	if t := InternalToken(); t == "" || looksWeak(t) {
		return fmt.Errorf("INTERNAL_SERVICE_TOKEN must be set to a strong, non-placeholder value in production")
	}
	// The DB password is embedded in the connection URL — reject placeholder creds.
	for _, k := range []string{"AUTH_DATABASE_URL", "USER_DATABASE_URL", "DATABASE_URL"} {
		if v := os.Getenv(k); v != "" && looksWeak(v) {
			return fmt.Errorf("%s must not use a placeholder database password in production", k)
		}
	}
	return nil
}

// Getenv returns the value of an env var or a fallback default.
func Getenv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// MustEnv returns the value of an env var or panics if unset.
func MustEnv(key string) string {
	v := os.Getenv(key)
	if v == "" {
		panic(fmt.Sprintf("required env var %s is not set", key))
	}
	return v
}

// GetenvInt parses an int env var with a fallback.
func GetenvInt(key string, fallback int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return fallback
}

// GetenvDuration parses a seconds-valued env var into a Duration.
func GetenvDuration(key string, fallbackSeconds int) time.Duration {
	return time.Duration(GetenvInt(key, fallbackSeconds)) * time.Second
}

// JWTConfig holds JWT signing settings shared across services.
type JWTConfig struct {
	Secret     string
	Issuer     string
	AccessTTL  time.Duration
	RefreshTTL time.Duration
}

// LoadJWT builds a JWTConfig from the environment.
func LoadJWT() JWTConfig {
	return JWTConfig{
		Secret:     Getenv("JWT_SECRET", DefaultJWTSecret),
		Issuer:     Getenv("JWT_ISSUER", "iam-auth"),
		AccessTTL:  GetenvDuration("ACCESS_TOKEN_TTL", 900),
		RefreshTTL: GetenvDuration("REFRESH_TOKEN_TTL", 604800),
	}
}
