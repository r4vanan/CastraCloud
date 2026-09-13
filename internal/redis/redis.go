// Package redis provides Redis-backed rate limiting and dynamic IP blocklists
// for the WAF gateway.
package redis

import (
	"context"
	"fmt"
	"time"

	goredis "github.com/redis/go-redis/v9"
)

// Client wraps the Redis connection.
type Client struct {
	rdb *goredis.Client
}

// New connects to Redis.
func New(ctx context.Context, addr, password string) (*Client, error) {
	rdb := goredis.NewClient(&goredis.Options{
		Addr:     addr,
		Password: password,
	})
	if err := rdb.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("redis: %w", err)
	}
	return &Client{rdb: rdb}, nil
}

// Close releases the connection.
func (c *Client) Close() error { return c.rdb.Close() }

// RateLimiter enforces a fixed-window request limit per key.
type RateLimiter struct {
	c     *Client
	limit int64
	win   time.Duration
}

// NewRateLimiter returns a limiter allowing `limit` requests per `win`.
func NewRateLimiter(c *Client, limit int64, win time.Duration) *RateLimiter {
	return &RateLimiter{c: c, limit: limit, win: win}
}

// Allow returns true if the request is within the limit, and increments the
// counter atomically.
func (r *RateLimiter) Allow(ctx context.Context, key string) (bool, int64, error) {
	pipe := r.c.rdb.TxPipeline()
	incr := pipe.Incr(ctx, key)
	pipe.Expire(ctx, key, r.win)
	if _, err := pipe.Exec(ctx); err != nil {
		return false, 0, err
	}
	count := incr.Val()
	return count <= r.limit, count, nil
}

// Reset clears the counter for a key.
func (r *RateLimiter) Reset(ctx context.Context, key string) error {
	return r.c.rdb.Del(ctx, key).Err()
}

// BlockIP adds an IP to the dynamic blocklist with a TTL.
func (c *Client) BlockIP(ctx context.Context, ip string, ttl time.Duration) error {
	return c.rdb.Set(ctx, blockKey(ip), "1", ttl).Err()
}

// IsBlocked reports whether an IP is on the blocklist.
func (c *Client) IsBlocked(ctx context.Context, ip string) (bool, error) {
	n, err := c.rdb.Exists(ctx, blockKey(ip)).Result()
	if err != nil {
		return false, err
	}
	return n > 0, nil
}

func blockKey(ip string) string { return "waf:block:" + ip }
