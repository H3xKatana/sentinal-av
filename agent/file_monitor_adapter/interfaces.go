package file_monitor_adapter

import (
	"time"
)

// SuspiciousEvent represents a potentially malicious activity detected
type SuspiciousEvent struct {
	ID          string    `json:"id"`
	Timestamp   time.Time `json:"timestamp"`
	EventType   string    `json:"event_type"`   // "file_created", "high_cpu", "high_memory", etc.
	Description string    `json:"description"`
	Severity    string    `json:"severity"`     // "low", "medium", "high", "critical"
	FilePath    string    `json:"file_path,omitempty"`
	ProcessName string    `json:"process_name,omitempty"`
	ProcessID   int       `json:"process_id,omitempty"`
	Details     map[string]interface{} `json:"details,omitempty"`
}

// MonitorConfig holds configuration for the file monitor
type MonitorConfig struct {
	ScanInterval    time.Duration   `json:"scan_interval"`
	SuspiciousPaths []string        `json:"suspicious_paths"` // Paths to monitor for new files
	CPULimit        float64         `json:"cpu_limit"`        // CPU usage threshold (percentage)
	MemoryLimit     float64         `json:"memory_limit"`     // Memory usage threshold (percentage)
	WatchProcesses  []string        `json:"watch_processes"`  // Specific processes to monitor
}

// Monitor defines the interface for system monitoring
type Monitor interface {
	// Start begins monitoring in the background
	Start() error
	
	// Stop ceases monitoring
	Stop() error
	
	// IsRunning returns whether monitoring is active
	IsRunning() bool
	
	// GetEvents returns a channel of detected suspicious events
	GetEvents() <-chan SuspiciousEvent
	
	// GetLastEvents returns the most recent suspicious events
	GetLastEvents(count int) []SuspiciousEvent
}