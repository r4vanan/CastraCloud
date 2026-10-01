// Command api runs the CastraCloud control-plane API server.
package main

import (
	"context"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/castracloud/castracloud/internal/ai"
	"github.com/castracloud/castracloud/internal/api"
	"github.com/castracloud/castracloud/internal/auth"
	"github.com/castracloud/castracloud/internal/config"
	_ "github.com/castracloud/castracloud/internal/connector/aws"
	_ "github.com/castracloud/castracloud/internal/connector/azure"
	_ "github.com/castracloud/castracloud/internal/connector/gcp"
	"github.com/castracloud/castracloud/internal/logging"
	"github.com/castracloud/castracloud/internal/store"
)

func main() {
	log := logging.New(config.Env("LOG_LEVEL", "info"))
	ctx := context.Background()
	jwtSecret, err := config.MustEnv("JWT_SECRET")
	if err != nil {
		log.Error("configuration failed", "error", err)
		os.Exit(1)
	}

	db, err := store.New(ctx, config.Postgres())
	if err != nil {
		log.Error("database connect failed", "error", err)
		os.Exit(1)
	}
	defer db.Close()

	if err := db.Migrate(ctx, config.Env("MIGRATIONS_DIR", "migrations")); err != nil {
		log.Error("migrations failed", "error", err)
		os.Exit(1)
	}

	srv := api.NewServer(db, log, jwtSecret, config.EnvDuration("JWT_TTL", time.Hour))

	if issuer := config.Env("OIDC_ISSUER", ""); issuer != "" {
		oidcCfg := auth.OIDCConfig{
			Issuer:       issuer,
			ClientID:     config.Env("OIDC_CLIENT_ID", ""),
			ClientSecret: config.Env("OIDC_CLIENT_SECRET", ""),
			RedirectURL:  config.Env("OIDC_REDIRECT_URL", ""),
			TenantSlug:   config.Env("OIDC_TENANT_SLUG", "default"),
		}
		if client, err := auth.NewOIDCClient(oidcCfg); err != nil {
			log.Error("oidc init failed", "error", err)
		} else {
			srv.EnableOIDC(client, oidcCfg.TenantSlug, config.Env("OIDC_REDIRECT_AFTER", "http://localhost:3000/"))
			log.Info("OIDC SSO enabled", "issuer", issuer)
		}
	}

	if key := config.Env("AI_API_KEY", ""); key != "" {
		model := config.Env("AI_MODEL", "gpt-4o-mini")
		if client, err := ai.New(ai.Config{
			BaseURL: config.Env("AI_BASE_URL", "https://api.openai.com/v1"),
			APIKey:  key,
			Model:   model,
		}); err != nil {
			log.Error("ai init failed", "error", err)
		} else {
			srv.EnableAI(client)
			log.Info("AI assistant enabled", "model", model)
		}
	}

	// Continuous scanning: periodically re-scan all configured connectors.
	scanInterval := config.EnvDuration("SCAN_INTERVAL", 24*time.Hour)
	srv.ScheduleScans(ctx, scanInterval)
	log.Info("scheduled scanning enabled", "interval", scanInterval.String())

	addr := ":" + config.Env("API_PORT", "8080")
	server := &http.Server{Addr: addr, Handler: srv.Router()}

	go func() {
		log.Info("API listening", "addr", addr)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Error("server error", "error", err)
			os.Exit(1)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop

	log.Info("shutting down")
	_ = server.Shutdown(ctx)
}
