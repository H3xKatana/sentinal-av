package auth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/0xA1M/sentinel-server/internal/models"
)

// ContextKey is used to store values in request context
type ContextKey string

const (
	UserContextKey ContextKey = "user"
)

// AuthMiddleware is a middleware that validates JWT tokens
func (s *Service) AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Extract token from Authorization header
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			http.Error(w, "Authorization header is required", http.StatusUnauthorized)
			return
		}

		// Expect format: "Bearer <token>"
		tokenParts := strings.Split(authHeader, " ")
		if len(tokenParts) != 2 || tokenParts[0] != "Bearer" {
			http.Error(w, "Authorization header must be in format 'Bearer <token>'", http.StatusUnauthorized)
			return
		}

		tokenString := tokenParts[1]

		// Validate the token
		user, err := s.ValidateToken(tokenString)
		if err != nil {
			if errors.Is(err, ErrUserNotFound) {
				http.Error(w, "User not found", http.StatusUnauthorized)
			} else {
				http.Error(w, fmt.Sprintf("Invalid token: %v", err), http.StatusUnauthorized)
			}
			return
		}

		// Add user to request context
		ctx := context.WithValue(r.Context(), UserContextKey, user)
		r = r.WithContext(ctx)

		// Call the next handler
		next.ServeHTTP(w, r)
	})
}

// RequireRoleMiddleware ensures the user has a specific role
func (s *Service) RequireRoleMiddleware(requiredRole string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Get user from context
		user, ok := r.Context().Value(UserContextKey).(*models.User)
		if !ok || user == nil {
			http.Error(w, "User not authenticated", http.StatusUnauthorized)
			return
		}

		// Check user role
		if user.Role != requiredRole && user.Role != "admin" {
			http.Error(w, "Insufficient permissions", http.StatusForbidden)
			return
		}

		// Call the next handler
		next.ServeHTTP(w, r)
	})
}

// GetUserFromContext retrieves the authenticated user from request context
func GetUserFromContext(ctx context.Context) (*models.User, error) {
	user, ok := ctx.Value(UserContextKey).(*models.User)
	if !ok || user == nil {
		return nil, errors.New("user not found in context")
	}
	return user, nil
}