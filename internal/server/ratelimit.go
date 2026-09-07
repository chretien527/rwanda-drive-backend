package server

import (
	"net/http"
	"sync"
	"time"

	"github.com/0xEmmyb2/CipherPass/internal/config"
)

// RateLimiter provides per-key rate limiting using a sliding window counter
type RateLimiter struct {
	mu       sync.Mutex
	windows  map[string]*window
	limit    int
	windowSize time.Duration
	logger   config.LoggerInterface
}

type window struct {
	count    int
	startsAt time.Time
}

// NewRateLimiter creates a new rate limiter
func NewRateLimiter(limit int, windowSize time.Duration, logger config.LoggerInterface) *RateLimiter {
	rl := &RateLimiter{
		windows:    make(map[string]*window),
		limit:      limit,
		windowSize: windowSize,
		logger:     logger,
	}

	// Cleanup expired windows periodically
	go rl.cleanup()

	return rl
}

// Allow checks if a request from the given key should be allowed
func (rl *RateLimiter) Allow(key string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	w, exists := rl.windows[key]

	if !exists || now.After(w.startsAt.Add(rl.windowSize)) {
		// New window
		rl.windows[key] = &window{
			count:    1,
			startsAt: now,
		}
		return true
	}

	if w.count >= rl.limit {
		return false
	}

	w.count++
	return true
}

// cleanup removes expired windows every minute
func (rl *RateLimiter) cleanup() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		rl.mu.Lock()
		now := time.Now()
		for key, w := range rl.windows {
			if now.After(w.startsAt.Add(rl.windowSize)) {
				delete(rl.windows, key)
			}
		}
		rl.mu.Unlock()
	}
}

// RateLimitMiddleware returns middleware that rate-limits by IP + path
func RateLimitMiddleware(limiter *RateLimiter, logger config.LoggerInterface) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			key := r.RemoteAddr + ":" + r.URL.Path

			if !limiter.Allow(key) {
				logger.WithFields(map[string]interface{}{
					"remote": r.RemoteAddr,
					"path":   r.URL.Path,
				}).Warn("Rate limit exceeded")

				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("Retry-After", "60")
				w.WriteHeader(http.StatusTooManyRequests)
				w.Write([]byte(`{"error":"too many requests, please try again later","code":"RATE_LIMITED"}`))
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
