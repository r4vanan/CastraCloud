// Command waf runs the CastraCloud Web Application Firewall gateway.
package main

import (
	"context"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"syscall"

	"github.com/castracloud/castracloud/internal/config"
	"github.com/castracloud/castracloud/internal/logging"
	rediscache "github.com/castracloud/castracloud/internal/redis"
	"github.com/castracloud/castracloud/internal/waf"
)

func main() {
	log := logging.New(config.Env("LOG_LEVEL", "info"))

	upstream, err := url.Parse(config.Env("WAF_UPSTREAM", "http://localhost:8080"))
	if err != nil {
		log.Error("invalid WAF_UPSTREAM", "error", err)
		os.Exit(1)
	}

	ctx := context.Background()
	rc, err := rediscache.New(ctx, config.Redis(), config.Env("REDIS_PASS", ""))
	if err != nil {
		log.Error("redis connect failed", "error", err)
		os.Exit(1)
	}
	defer rc.Close()

	cfg := waf.Config{
		Upstream:     upstream,
		RateLimit:    int64(config.EnvInt("WAF_RATE_LIMIT", 100)),
		RateWindow:   config.EnvDuration("WAF_RATE_WINDOW", 60*1e9),
		MaxBodyBytes: int64(config.EnvInt("WAF_MAX_BODY_BYTES", 65536)),
		BehindProxy:  config.Env("WAF_BEHIND_PROXY", "false") == "true",
	}

	handler := waf.NewHandler(cfg, ruleset(log), rc, log)

	addr := ":" + config.Env("WAF_PORT", "8000")
	srv := &http.Server{
		Addr:    addr,
		Handler: handler,
	}

	cert, key := config.Env("WAF_TLS_CERT", ""), config.Env("WAF_TLS_KEY", "")
	go func() {
		log.Info("WAF gateway listening", "addr", addr, "upstream", upstream.String(),
			"tls", cert != "" && key != "")
		var err error
		if cert != "" && key != "" {
			err = srv.ListenAndServeTLS(cert, key)
		} else {
			err = srv.ListenAndServe()
		}
		if err != nil && err != http.ErrServerClosed {
			log.Error("server error", "error", err)
			os.Exit(1)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop

	log.Info("shutting down")
	_ = srv.Shutdown(ctx)
}

// ruleset returns the default rules merged with any OWASP CRS file import.
func ruleset(log *slog.Logger) []waf.Rule {
	rules := waf.DefaultRuleset()
	crsFile := config.Env("WAF_CRS_FILE", "")
	if crsFile == "" {
		return rules
	}
	f, err := os.Open(crsFile)
	if err != nil {
		log.Warn("cannot open CRS file", "path", crsFile, "error", err)
		return rules
	}
	defer f.Close()
	imported, err := waf.ImportCRS(f)
	if err != nil {
		log.Warn("CRS import failed", "path", crsFile, "error", err)
		return rules
	}
	return append(rules, imported...)
}
