package waf

import (
	"bytes"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"time"

	rediscache "github.com/castracloud/castracloud/internal/redis"
)

// Config configures a WAF gateway instance.
type Config struct {
	Upstream     *url.URL
	RateLimit    int64
	RateWindow   time.Duration
	MaxBodyBytes int64
	BehindProxy  bool // trust X-Forwarded-For for client IP
}

// Handler is the WAF reverse proxy. It runs the pipeline:
// blocklist → subject build → rate limit → rule engine → proxy.
type Handler struct {
	cfg     Config
	rules   []Rule
	limiter *rediscache.RateLimiter
	redis   *rediscache.Client
	log     *slog.Logger
	proxy   *httputil.ReverseProxy
}

// NewHandler builds a WAF handler with the given rules and Redis client.
func NewHandler(cfg Config, rules []Rule, rc *rediscache.Client, log *slog.Logger) *Handler {
	proxy := httputil.NewSingleHostReverseProxy(cfg.Upstream)
	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		log.Error("upstream error", "error", err)
		http.Error(w, "bad gateway", http.StatusBadGateway)
	}
	h := &Handler{
		cfg:     cfg,
		rules:   rules,
		limiter: rediscache.NewRateLimiter(rc, cfg.RateLimit, cfg.RateWindow),
		redis:   rc,
		log:     log,
		proxy:   proxy,
	}
	return h
}

// SetRules atomically swaps the active ruleset (used by the control plane).
func (h *Handler) SetRules(rules []Rule) { h.rules = rules }

// ClientIP extracts the caller IP, honoring X-Forwarded-For when configured.
func (h *Handler) ClientIP(r *http.Request) string {
	if h.cfg.BehindProxy {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			return strings.TrimSpace(strings.Split(xff, ",")[0])
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	ip := h.ClientIP(r)

	if blocked, _ := h.redis.IsBlocked(ctx, ip); blocked {
		h.respondBlock(w, http.StatusForbidden, "IP blocklisted")
		return
	}

	allowed, count, err := h.limiter.Allow(ctx, "waf:rl:"+ip)
	if err != nil {
		h.log.Warn("rate limiter unavailable", "error", err)
	} else if !allowed {
		w.Header().Set("Retry-After", strconv.Itoa(int(h.cfg.RateWindow.Seconds())))
		h.respondBlock(w, http.StatusTooManyRequests, "rate limit exceeded")
		return
	}

	subject, err := h.buildSubject(r)
	if err != nil {
		h.log.Warn("subject build failed", "error", err)
	}

	for _, rule := range h.rules {
		if rule.MatchAll(subject) {
			h.log.LogAttrs(ctx, slog.LevelWarn, "waf_block",
				slog.String("ip", ip), slog.String("rule", rule.ID),
				slog.String("path", r.URL.Path), slog.Int64("rl_count", count))
			if rule.Action == ActionBlock {
				h.respondBlock(w, http.StatusForbidden, "blocked by rule "+rule.ID)
				return
			}
		}
	}

	h.log.LogAttrs(ctx, slog.LevelInfo, "request",
		slog.String("ip", ip), slog.String("method", r.Method),
		slog.String("path", r.URL.Path), slog.Int64("rl_count", count))
	h.proxy.ServeHTTP(w, r)
}

// buildSubject reads and buffers the body so the engine can inspect it while
// leaving it intact for the upstream.
func (h *Handler) buildSubject(r *http.Request) (*Subject, error) {
	body := ""
	if r.Body != nil {
		max := h.cfg.MaxBodyBytes
		if max == 0 {
			max = 1 << 16 // 64 KiB default
		}
		data, err := io.ReadAll(io.LimitReader(r.Body, max))
		if err != nil {
			return nil, err
		}
		body = string(data)
		r.Body = io.NopCloser(bytes.NewReader(data))
	}
	decodedQuery, _ := url.QueryUnescape(r.URL.RawQuery)
	decodedURI := r.URL.Path
	if decodedQuery != "" {
		decodedURI += "?" + decodedQuery
	}

	return &Subject{
		IP:          h.ClientIP(r),
		Method:      r.Method,
		URI:         decodedURI,
		Path:        r.URL.Path,
		Query:       r.URL.RawQuery,
		Headers:     r.Header,
		Body:        body,
		UserAgent:   r.UserAgent(),
		ContentType: r.Header.Get("Content-Type"),
	}, nil
}

func (h *Handler) respondBlock(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(code)
	_, _ = io.WriteString(w, "<html><body><h1>"+http.StatusText(code)+
		"</h1><p>"+msg+"</p><hr><p>Protected by CastraCloud WAF</p></body></html>")
}
