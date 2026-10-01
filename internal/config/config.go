// Package config loads service configuration from environment variables,
// keeping each binary self-contained and 12-factor friendly.
package config

import (
	"fmt"
	"os"
	"strconv"
	"time"
)

// Env reads an environment variable or returns a default.
func Env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// EnvInt reads an integer environment variable or returns a default.
func EnvInt(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

// EnvDuration reads a duration environment variable or returns a default.
func EnvDuration(key string, def time.Duration) time.Duration {
	if v := os.Getenv(key); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	}
	return def
}

// MustEnv reads a required environment variable, returning an error if unset.
func MustEnv(key string) (string, error) {
	v := os.Getenv(key)
	if v == "" {
		return "", fmt.Errorf("required environment variable %s is not set", key)
	}
	return v, nil
}

// Postgres returns a DSN for the platform database.
func Postgres() string {
	return fmt.Sprintf(
		"postgres://%s:%s@%s:%s/%s?sslmode=%s",
		Env("DB_USER", "castracloud"),
		Env("DB_PASS", "castracloud"),
		Env("DB_HOST", "localhost"),
		Env("DB_PORT", "5432"),
		Env("DB_NAME", "castracloud"),
		Env("DB_SSLMODE", "disable"),
	)
}
