package vt_adapter

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// VTResponse represents the response from VirusTotal API
type VTResponse struct {
	Data struct {
		ID         string                 `json:"id"`
		Type       string                 `json:"type"`
		Attributes map[string]interface{} `json:"attributes"`
	} `json:"data"`
}

// VTAnalysisResponse represents the analysis response
type VTAnalysisResponse struct {
	Data struct {
		ID         string                 `json:"id"`
		Type       string                 `json:"type"`
		Attributes map[string]interface{} `json:"attributes"`
	} `json:"data"`
}

const (
	// API limits
	RATE_LIMIT_PER_MINUTE = 4
	MAX_REQUESTS_PER_DAY  = 500
)

// min returns the smaller of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// VTAdapter represents the VirusTotal adapter
type VTAdapter struct {
	rateLimiter *RateLimiter
	apiKey      string
	httpClient  *http.Client
}

// RateLimiter manages API call frequency
type RateLimiter struct {
	minuteLimit    *TokenBucket
	dailyLimit     *TokenBucket
	requestHistory []time.Time
	mu             sync.Mutex // to protect access to rate limiting resources
}

// TokenBucket implements a token bucket rate limiting algorithm
type TokenBucket struct {
	tokens       int
	capacity     int
	refillRate   time.Duration
	lastRefill   time.Time
	mu           sync.Mutex
}

// NewTokenBucket creates a new token bucket
func NewTokenBucket(capacity int, refillRate time.Duration) *TokenBucket {
	return &TokenBucket{
		tokens:     capacity,
		capacity:   capacity,
		refillRate: refillRate,
		lastRefill: time.Now(),
	}
}

// Allow checks if a request is allowed under rate limits
func (tb *TokenBucket) Allow() bool {
	tb.mu.Lock()
	defer tb.mu.Unlock()

	now := time.Now()
	elapsed := now.Sub(tb.lastRefill)

	// Refill tokens based on time elapsed
	tokensToAdd := int(elapsed / tb.refillRate)
	tb.tokens = min(tb.capacity, tb.tokens+tokensToAdd)
	tb.lastRefill = now

	if tb.tokens > 0 {
		tb.tokens--
		return true
	}

	return false
}

// NewRateLimiter creates a new rate limiter with configured limits
func NewRateLimiter() *RateLimiter {
	// 4 requests per minute (4/60 per second)
	minuteLimit := NewTokenBucket(RATE_LIMIT_PER_MINUTE, time.Second*15) // 60s/4 = 15s per token

	// 500 requests per day (500/(24*60*60) per second)
	dailyLimit := NewTokenBucket(MAX_REQUESTS_PER_DAY, time.Second*(24*60*60)/MAX_REQUESTS_PER_DAY)

	return &RateLimiter{
		minuteLimit: minuteLimit,
		dailyLimit:  dailyLimit,
		requestHistory: make([]time.Time, 0),
	}
}

// Allow checks if a request is allowed under all rate limits
func (rl *RateLimiter) Allow() bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	// Check both minute and daily limits
	minuteOk := rl.minuteLimit.Allow()
	dailyOk := rl.dailyLimit.Allow()

	return minuteOk && dailyOk
}

// NewVTAdapter creates a new VirusTotal adapter instance
func NewVTAdapter(apiKey string) (*VTAdapter, error) {
	if apiKey == "" {
		return nil, fmt.Errorf("VirusTotal API key is required")
	}

	adapter := &VTAdapter{
		rateLimiter: NewRateLimiter(),
		apiKey:      apiKey,
		httpClient:  &http.Client{Timeout: 30 * time.Second},
	}

	return adapter, nil
}

// CalculateFileHash calculates the SHA256 hash of a file
func CalculateFileHash(filePath string) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	hasher := sha256.New()
	if _, err := io.Copy(hasher, file); err != nil {
		return "", err
	}

	hashBytes := hasher.Sum(nil)
	return hex.EncodeToString(hashBytes), nil
}

// SubmitFile submits a file to VirusTotal for scanning
func (vta *VTAdapter) SubmitFile(filePath string) (*VTAnalysisResponse, error) {
	if !vta.rateLimiter.Allow() {
		return nil, fmt.Errorf("rate limit exceeded")
	}

	// Open the file to upload
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %v", err)
	}
	defer file.Close()

	// Create form data for file upload
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)

	// Create form file field
	part, err := writer.CreateFormFile("file", filepath.Base(filePath))
	if err != nil {
		return nil, fmt.Errorf("failed to create form file: %v", err)
	}

	// Copy file content to form
	_, err = io.Copy(part, file)
	if err != nil {
		return nil, fmt.Errorf("failed to copy file: %v", err)
	}

	// Close the writer to finalize form
	writer.Close()

	// Create HTTP request
	req, err := http.NewRequest("POST", "https://www.virustotal.com/api/v3/files", &body)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}

	// Set headers
	req.Header.Set("x-apikey", vta.apiKey)
	req.Header.Set("Content-Type", writer.FormDataContentType())

	// Send the request
	resp, err := vta.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %v", err)
	}
	defer resp.Body.Close()

	// Check response status
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("API returned error status: %d", resp.StatusCode)
	}

	// Parse the response
	var analysisResp VTAnalysisResponse
	if err := json.NewDecoder(resp.Body).Decode(&analysisResp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %v", err)
	}

	return &analysisResp, nil
}

// GetFileReport retrieves a report for a file by its hash
func (vta *VTAdapter) GetFileReport(fileHash string) (*VTResponse, error) {
	if !vta.rateLimiter.Allow() {
		return nil, fmt.Errorf("rate limit exceeded")
	}

	// Create HTTP request
	req, err := http.NewRequest("GET", fmt.Sprintf("https://www.virustotal.com/api/v3/files/%s", fileHash), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}

	// Set headers
	req.Header.Set("x-apikey", vta.apiKey)

	// Send the request
	resp, err := vta.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %v", err)
	}
	defer resp.Body.Close()

	// Check response status
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("API returned error status: %d", resp.StatusCode)
	}

	// Parse the response
	var fileResp VTResponse
	if err := json.NewDecoder(resp.Body).Decode(&fileResp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %v", err)
	}

	return &fileResp, nil
}

// SubmitHash submits a hash to VirusTotal for analysis
func (vta *VTAdapter) SubmitHash(hashValue string) (*VTResponse, error) {
	if !vta.rateLimiter.Allow() {
		return nil, fmt.Errorf("rate limit exceeded")
	}

	// A hash submission is typically just requesting a report on that hash
	// if it exists in VirusTotal's database
	return vta.GetFileReport(hashValue)
}

// IsFileMalicious checks if a file is reported as malicious by VirusTotal
func (vta *VTAdapter) IsFileMalicious(filePath string) (bool, error) {
	hash, err := CalculateFileHash(filePath)
	if err != nil {
		return false, fmt.Errorf("failed to calculate file hash: %v", err)
	}

	report, err := vta.GetFileReport(hash)
	if err != nil {
		return false, fmt.Errorf("failed to get report for file: %v", err)
	}

	// Check if the file has any malicious detections
	// In VirusTotal API, the "last_analysis_stats" field contains:
	// - "malicious" - number of engines marking the file as malicious
	if report != nil {
		// Accessing the attributes object within the report
		attrs := report.Data.Attributes
		if lastAnalysisStats, ok := attrs["last_analysis_stats"].(map[string]interface{}); ok {
			if maliciousVal, ok := lastAnalysisStats["malicious"]; ok {
				if maliciousCount, ok := maliciousVal.(float64); ok {
					// If any engine marked it as malicious, return true
					return int(maliciousCount) > 0, nil
				}
			}
		}
	}

	return false, nil
}

// Close cleans up resources used by the adapter
func (vta *VTAdapter) Close() error {
	// Close the HTTP client if needed
	vta.httpClient.CloseIdleConnections()
	return nil
}

// IsFileMaliciousFromHash checks if a hash is reported as malicious by VirusTotal
// This function is similar to IsFileMalicious but works directly with a hash
func (vta *VTAdapter) IsFileMaliciousFromHash(fileHash string) (bool, error) {
	report, err := vta.GetFileReport(fileHash)
	if err != nil {
		return false, fmt.Errorf("failed to get report for hash: %v", err)
	}

	// Check if the file has any malicious detections
	// In VirusTotal API, the "last_analysis_stats" field contains:
	// - "malicious" - number of engines marking the file as malicious
	if report != nil {
		// Accessing the attributes object within the report
		attrs := report.Data.Attributes
		if lastAnalysisStats, ok := attrs["last_analysis_stats"].(map[string]interface{}); ok {
			if maliciousVal, ok := lastAnalysisStats["malicious"]; ok {
				if maliciousCount, ok := maliciousVal.(float64); ok {
					// If any engine marked it as malicious, return true
					return int(maliciousCount) > 0, nil
				}
			}
		}
	}

	return false, nil
}