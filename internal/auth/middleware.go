package auth

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/0xEmmyb2/CipherPass/internal/config"
)

// Context key types to avoid key collisions
type contextKey string

const (
	UserIDKey contextKey = "user_id"
	EmailKey  contextKey = "email"
	RoleKey   contextKey = "role"
)

// Middleware provides authentication and authorization middleware
type Middleware struct {
	service *Service
	logger  config.LoggerInterface
}

// NewMiddleware creates a new auth middleware
func NewMiddleware(service *Service, logger config.LoggerInterface) *Middleware {
	return &Middleware{
		service: service,
		logger:  logger,
	}
}

// Authenticate extracts and validates the JWT from the Authorization header,
// then attaches user_id, email, and role to the request context.
func (m *Middleware) Authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			writeJSON(w, http.StatusUnauthorized, map[string]string{
				"error": "missing authorization header",
				"code":  "AUTH_MISSING_HEADER",
			})
			return
		}

		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
			writeJSON(w, http.StatusUnauthorized, map[string]string{
				"error": "invalid authorization header format",
				"code":  "AUTH_INVALID_HEADER",
			})
			return
		}

		claims, err := m.service.ValidateAccessToken(parts[1])
		if err != nil {
			m.logger.WithError(err).Warn("Invalid access token")
			writeJSON(w, http.StatusUnauthorized, map[string]string{
				"error": "invalid or expired token",
				"code":  err.(Error).Code,
			})
			return
		}

		// Attach user info to context
		ctx := context.WithValue(r.Context(), UserIDKey, claims.UserID)
		ctx = context.WithValue(ctx, EmailKey, claims.Email)
		ctx = context.WithValue(ctx, RoleKey, claims.Role)

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// RequireRole returns middleware that restricts access to users with one of the given roles
func (m *Middleware) RequireRole(roles ...string) func(http.Handler) http.Handler {
	roleSet := make(map[string]bool, len(roles))
	for _, r := range roles {
		roleSet[r] = true
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			role, ok := r.Context().Value(RoleKey).(string)
			if !ok {
				writeJSON(w, http.StatusUnauthorized, map[string]string{
					"error": "not authenticated",
					"code":  "AUTH_NOT_AUTHENTICATED",
				})
				return
			}

			if !roleSet[role] {
				m.logger.WithFields(map[string]interface{}{
					"user_id": GetUserID(r.Context()),
					"role":    role,
					"path":    r.URL.Path,
				}).Warn("Unauthorized access attempt")
				writeJSON(w, http.StatusForbidden, map[string]string{
					"error": "insufficient permissions",
					"code":  "AUTH_FORBIDDEN",
				})
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// --- Context helper functions ---

// GetUserID extracts the user ID from the request context
func GetUserID(ctx context.Context) string {
	id, _ := ctx.Value(UserIDKey).(string)
	return id
}

// GetEmail extracts the email from the request context
func GetEmail(ctx context.Context) string {
	email, _ := ctx.Value(EmailKey).(string)
	return email
}

// GetRole extracts the role from the request context
func GetRole(ctx context.Context) string {
	role, _ := ctx.Value(RoleKey).(string)
	return role
}

// writeJSON sends a JSON error response
func writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}
