package server

import (
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/0xEmmyb2/CipherPass/internal/config"
	"github.com/google/uuid"
)

// responseWriter wraps http.ResponseWriter to capture status code
type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

func newResponseWriter(w http.ResponseWriter) *responseWriter {
	return &responseWriter{w, http.StatusOK}
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

// requestIDMiddleware adds a unique request ID to each request
func requestIDMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestID := r.Header.Get("X-Request-ID")
		if requestID == "" {
			requestID = uuid.New().String()
		}
		w.Header().Set("X-Request-ID", requestID)
		next.ServeHTTP(w, r)
	})
}

// loggingMiddleware logs each HTTP request with method, path, status, and duration
func loggingMiddleware(logger *config.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			wrapped := newResponseWriter(w)

			next.ServeHTTP(wrapped, r)

			logger.WithFields(map[string]interface{}{
				"method":     r.Method,
				"path":       r.URL.Path,
				"status":     wrapped.statusCode,
				"duration":   time.Since(start).String(),
				"remote":     r.RemoteAddr,
				"request_id": w.Header().Get("X-Request-ID"),
			}).Info("HTTP request")
		})
	}
}

// recoveryMiddleware catches panics and returns 500
func recoveryMiddleware(logger *config.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				if err := recover(); err != nil {
					logger.WithFields(map[string]interface{}{
						"error":  fmt.Sprintf("%v", err),
						"path":   r.URL.Path,
						"method": r.Method,
					}).Error("Panic recovered")

					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusInternalServerError)
					w.Write([]byte(`{"error":"internal server error","code":"INTERNAL_ERROR"}`))
				}
			}()
			next.ServeHTTP(w, r)
		})
	}
}

// corsMiddleware adds CORS headers based on configuration
func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		
		// Always set CORS headers before checking origin
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Request-ID, X-Idempotency-Key")
		w.Header().Set("Access-Control-Expose-Headers", "X-Request-ID")
		w.Header().Set("Access-Control-Max-Age", "86400")
		
		// Handle preflight immediately
		if r.Method == http.MethodOptions {
			if origin != "" {
				allowedOrigins := os.Getenv("CORS_ALLOWED_ORIGINS")
				if allowedOrigins == "" {
					allowedOrigins = "http://localhost:3000,https://docproof2.vercel.app"
				}

				allowed := false
				for _, allowedOrigin := range strings.Split(allowedOrigins, ",") {
					if strings.TrimSpace(allowedOrigin) == origin {
						allowed = true
						break
					}
				}

				// In development, allow any localhost or 127.0.0.1 origin.
				env := os.Getenv("ENVIRONMENT")
				isDevelopment := env == "" || env == "development"
				if !allowed && isDevelopment && (strings.Contains(origin, "localhost") || strings.Contains(origin, "127.0.0.1")) {
					allowed = true
				}

				if allowed {
					w.Header().Set("Access-Control-Allow-Origin", origin)
					w.Header().Set("Access-Control-Allow-Credentials", "true")
				}
			}
			w.WriteHeader(http.StatusNoContent)
			return
		}

		// For actual requests, check origin
		if origin != "" {
			allowed := false
			
			// Get configured origins
			allowedOrigins := os.Getenv("CORS_ALLOWED_ORIGINS")
			if allowedOrigins == "" {
				allowedOrigins = "http://localhost:3000,https://docproof2.vercel.app"
			}
			
			// Check exact matches
			for _, o := range strings.Split(allowedOrigins, ",") {
				if strings.TrimSpace(o) == origin {
					allowed = true
					break
				}
			}
			
			// In development, allow any localhost or 127.0.0.1
			if !allowed {
				env := os.Getenv("ENVIRONMENT")
				isDevelopment := env == "" || env == "development"
				
				if isDevelopment && (strings.Contains(origin, "localhost") || strings.Contains(origin, "127.0.0.1")) {
					allowed = true
				}
			}
			
			if allowed {
				w.Header().Set("Access-Control-Allow-Origin", origin)
				w.Header().Set("Access-Control-Allow-Credentials", "true")
			}
		}

		next.ServeHTTP(w, r)
	})
}

// securityHeadersMiddleware adds standard security headers
func securityHeadersMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-XSS-Protection", "0") // Modern browsers: use CSP instead
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")

		// HSTS — enable in production/staging
		env := os.Getenv("ENVIRONMENT")
		if env == "production" || env == "staging" {
			w.Header().Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		}

		next.ServeHTTP(w, r)
	})
}
