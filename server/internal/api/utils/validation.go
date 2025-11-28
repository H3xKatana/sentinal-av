package utils

import (
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"golang.org/x/time/rate"
)

// InputValidationMiddleware validates incoming request data
func InputValidationMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Validate content type for POST/PUT requests
		if r.Method == "POST" || r.Method == "PUT" {
			contentType := r.Header.Get("Content-Type")
			if contentType != "" && !strings.Contains(contentType, "application/json") {
				http.Error(w, "Content-Type must be application/json", http.StatusBadRequest)
				return
			}
		}

		// Continue with the next handler
		next.ServeHTTP(w, r)
	})
}

// RateLimitMiddleware adds rate limiting to endpoints
func RateLimitMiddleware(r rate.Limit, burst int, window time.Duration) func(http.Handler) http.Handler {
	limiter := rate.NewLimiter(r, burst)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !limiter.Allow() {
				http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// ValidateEmail validates an email address
func ValidateEmail(email string) bool {
	re := regexp.MustCompile("^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$")
	return re.MatchString(email)
}

// ValidatePassword validates a password
func ValidatePassword(password string) error {
	if len(password) < 8 {
		return fmt.Errorf("password must be at least 8 characters long")
	}

	var (
		hasUpper  bool
		hasLower  bool
		hasNumber bool
		hasSymbol bool
	)

	for _, char := range password {
		switch {
		case char >= 'A' && char <= 'Z':
			hasUpper = true
		case char >= 'a' && char <= 'z':
			hasLower = true
		case char >= '0' && char <= '9':
			hasNumber = true
		default:
			hasSymbol = true
		}
	}

	if !hasUpper {
		return fmt.Errorf("password must contain at least one uppercase letter")
	}

	if !hasLower {
		return fmt.Errorf("password must contain at least one lowercase letter")
	}

	if !hasNumber {
		return fmt.Errorf("password must contain at least one number")
	}

	if !hasSymbol {
		return fmt.Errorf("password must contain at least one special character")
	}

	return nil
}

// ValidateUsername validates a username
func ValidateUsername(username string) bool {
	if len(username) < 3 || len(username) > 30 {
		return false
	}

	// Username should only contain alphanumeric characters and underscores
	re := regexp.MustCompile("^[a-zA-Z0-9_]+$")
	return re.MatchString(username)
}