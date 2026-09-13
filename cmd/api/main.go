// Command api runs the CastraCloud control-plane API server.
package main

import (
	"context"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/castracloud/castracloud/internal/api"
	"github.com/castracloud/castracloud/internal/auth"
	"github.com/castracloud/castracloud/internal/config"
	"github.com/castracloud/castracloud/internal/logging"
	"github.com/castracloud/castracloud/internal/store"
)

func main() {
	log := logging.New(config.Env("LOG_LEVEL", "info"))
	ctx := context.Background()

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

	srv := api.NewServer(db, log, config.Env("JWT_SECRET", ""), config.EnvDuration("JWT_TTL", time.Hour))

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
