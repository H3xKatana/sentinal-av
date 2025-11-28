package utils

import (
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/0xA1M/sentinel-server/internal/models"
	"github.com/gorilla/mux"
	"golang.org/x/time/rate"
)

// RateLimiter holds rate limiting information
type RateLimiter struct {
	// Map IP addresses to rate limiters
	ips map[string]*IPRateLimiter
	// Rate at which tokens are regenerated
	rate rate.Limit
	// Burst of requests allowed
	burst int
}

// IPRateLimiter holds the limiter for each IP
type IPRateLimiter struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

// NewRateLimiter creates a new rate limiter
func NewRateLimiter(r rate.Limit, burst int) *RateLimiter {
	return &RateLimiter{
		ips:   make(map[string]*IPRateLimiter),
		rate:  r,
		burst: burst,
	}
}

// AddIP adds a rate limiter for an IP address
func (rl *RateLimiter) AddIP(ip string) *IPRateLimiter {
	limiter := &IPRateLimiter{
		limiter:  rate.NewLimiter(rl.rate, rl.burst),
		lastSeen: time.Now(),
	}

	rl.ips[ip] = limiter

	return limiter
}

// GetIP returns the rate limiter for an IP address
func (rl *RateLimiter) GetIP(ip string) *IPRateLimiter {
	limiter, exists := rl.ips[ip]

	if !exists {
		return rl.AddIP(ip)
	}

	limiter.lastSeen = time.Now()
	return limiter
}

// RateLimitMiddleware returns a rate limiting middleware
func RateLimitMiddleware(r rate.Limit, burst int, defaultLimit int) mux.MiddlewareFunc {
	rateLimiter := NewRateLimiter(r, burst)

	// Clean up inactive IPs every 5 minutes
	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		for range ticker.C {
			// Delete IPs that have been inactive for more than 30 minutes
			for ip, limiter := range rateLimiter.ips {
				if time.Since(limiter.lastSeen) > 30*time.Minute {
					delete(rateLimiter.ips, ip)
				}
			}
		}
	}()

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip := getIP(r)

			limiter := rateLimiter.GetIP(ip)

			// Custom rate limit for specific paths
			limit := defaultLimit
			if strings.HasPrefix(r.URL.Path, "/api/login") {
				// Lower limits for login attempts to prevent brute force
				limit = 5
			} else if strings.HasPrefix(r.URL.Path, "/api/register") {
				// Lower limits for registration attempts
				limit = 3
			}

			if !limiter.limiter.AllowN(time.Now(), limit) {
				http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// Get IP address from request
func getIP(r *http.Request) string {
	// Check X-Forwarded-For header first
	forwarded := r.Header.Get("X-Forwarded-For")
	if forwarded != "" {
		// Take the first IP if multiple are provided
		ips := strings.Split(forwarded, ",")
		return strings.TrimSpace(ips[0])
	}

	// Check X-Real-IP header
	realIP := r.Header.Get("X-Real-IP")
	if realIP != "" {
		return realIP
	}

	// Fallback to RemoteAddr
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	return host
}

// InputValidationMiddleware validates input data
func InputValidationMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Add security headers
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")

		// For POST and PUT requests, validate content type
		if r.Method == "POST" || r.Method == "PUT" {
			contentType := r.Header.Get("Content-Type")
			if contentType != "" && !strings.HasPrefix(contentType, "application/json") &&
				!strings.HasPrefix(contentType, "multipart/form-data") &&
				!strings.HasPrefix(contentType, "application/x-www-form-urlencoded") {
				http.Error(w, "Invalid content type", http.StatusBadRequest)
				return
			}
		}

		// Validate paths to prevent path traversal
		if strings.Contains(r.URL.Path, "..") || strings.Contains(r.URL.Path, "/.") {
			http.Error(w, "Invalid path", http.StatusBadRequest)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// ValidateAgentData validates agent registration data
func ValidateAgentData(agent *models.Agent) error {
	if len(agent.Name) < 1 || len(agent.Name) > 100 {
		return fmt.Errorf("agent name must be between 1 and 100 characters")
	}

	if len(agent.Hostname) < 1 || len(agent.Hostname) > 255 {
		return fmt.Errorf("hostname must be between 1 and 255 characters")
	}

	if agent.Platform != "linux" && agent.Platform != "windows" && agent.Platform != "darwin" {
		return fmt.Errorf("platform must be one of: linux, windows, darwin")
	}

	// Validate IP address format
	if agent.IPAddress != "" {
		ip := net.ParseIP(agent.IPAddress)
		if ip == nil {
			return fmt.Errorf("invalid IP address")
		}
	}

	return nil
}

// ValidateScanResultData validates scan result data
func ValidateScanResultData(scanResult *models.ScanResult) error {
	if scanResult.ScanType != "full" && scanResult.ScanType != "quick" &&
		scanResult.ScanType != "custom" && scanResult.ScanType != "real-time" {
		return fmt.Errorf("scan type must be one of: full, quick, custom, real-time")
	}

	if scanResult.Status != "completed" && scanResult.Status != "failed" &&
		scanResult.Status != "in-progress" {
		return fmt.Errorf("scan status must be one of: completed, failed, in-progress")
	}

	// Validate file paths to prevent path traversal
	for _, path := range scanResult.FilePaths {
		if strings.Contains(path, "..") {
			return fmt.Errorf("invalid file path: path traversal detected")
		}
	}

	return nil
}

// ValidateThreatData validates threat data
func ValidateThreatData(threat *models.Threat) error {
	if len(threat.FilePath) == 0 {
		return fmt.Errorf("file path is required")
	}

	if threat.ThreatType != "malware" && threat.ThreatType != "heuristic" &&
		threat.ThreatType != "suspicious" {
		return fmt.Errorf("threat type must be one of: malware, heuristic, suspicious")
	}

	if threat.Severity != "low" && threat.Severity != "medium" &&
		threat.Severity != "high" && threat.Severity != "critical" {
		return fmt.Errorf("severity must be one of: low, medium, high, critical")
	}

	if threat.ActionTaken != "quarantined" && threat.ActionTaken != "blocked" &&
		threat.ActionTaken != "reported" {
		return fmt.Errorf("action taken must be one of: quarantined, blocked, reported")
	}

	return nil
}

// ValidateSignatureData validates signature data
func ValidateSignatureData(signature *models.Signature) error {
	if len(signature.Name) < 1 || len(signature.Name) > 100 {
		return fmt.Errorf("signature name must be between 1 and 100 characters")
	}

	if signature.Type != "yara" && signature.Type != "hash" && signature.Type != "heuristic" {
		return fmt.Errorf("signature type must be one of: yara, hash, heuristic")
	}

	if len(signature.Content) == 0 {
		return fmt.Errorf("signature content is required")
	}

	if len(signature.Content) > 10000 { // Limit signature content to prevent oversized payloads
		return fmt.Errorf("signature content too long")
	}

	if signature.HashType != "" && signature.HashType != "md5" && signature.HashType != "sha256" {
		return fmt.Errorf("hash type must be one of: md5, sha256, or empty")
	}

	if signature.Status != "active" && signature.Status != "inactive" && signature.Status != "deprecated" {
		return fmt.Errorf("signature status must be one of: active, inactive, deprecated")
	}

	return nil
}

// ValidateEventData validates event data
func ValidateEventData(event *models.Event) error {
	if event.EventType == "" {
		return fmt.Errorf("event type is required")
	}

	if len(event.EventType) > 100 {
		return fmt.Errorf("event type too long")
	}

	if event.EventSource != "agent" && event.EventSource != "signature" && event.EventSource != "heuristic" {
		return fmt.Errorf("event source must be one of: agent, signature, heuristic")
	}

	if event.Severity != "info" && event.Severity != "warning" &&
		event.Severity != "high" && event.Severity != "critical" {
		return fmt.Errorf("event severity must be one of: info, warning, high, critical")
	}

	if len(event.Data) > 10000 { // Limit event data to prevent oversized payloads
		return fmt.Errorf("event data too long")
	}

	return nil
}

// ValidateQuarantineData validates quarantine data
func ValidateQuarantineData(quarantine *models.Quarantine) error {
	if len(quarantine.OriginalPath) == 0 {
		return fmt.Errorf("original path is required")
	}

	if quarantine.Status != "quarantined" && quarantine.Status != "restored" && quarantine.Status != "deleted" {
		return fmt.Errorf("quarantine status must be one of: quarantined, restored, deleted")
	}

	return nil
}

// ValidateUserData validates user data
func ValidateUserData(user *models.User, isUpdate bool) error {
	if !isUpdate {
		// For new users, username is required
		if len(user.Username) < 3 || len(user.Username) > 50 {
			return fmt.Errorf("username must be between 3 and 50 characters")
		}
	}

	if user.Email != "" {
		// Basic email validation
		if !strings.Contains(user.Email, "@") || !strings.Contains(user.Email, ".") {
			return fmt.Errorf("invalid email format")
		}

		if len(user.Email) > 255 {
			return fmt.Errorf("email too long")
		}
	}

	if user.Role != "" && user.Role != "admin" && user.Role != "user" {
		return fmt.Errorf("role must be one of: admin, user")
	}

	return nil
}
