package common

import (
	"time"
)

// ScanResult represents the result of a scan operation
type ScanResult struct {
	ID          string    `json:"id"`
	AgentID     string    `json:"agent_id"`
	Timestamp   time.Time `json:"timestamp"`
	ScannedPath string    `json:"scanned_path"`
	Infected    []string  `json:"infected"`
	ScanTime    string    `json:"scan_time"` // Duration as string
	Error       string    `json:"error,omitempty"`
}

// ThreatReport represents a detected threat
type ThreatReport struct {
	ID          string    `json:"id"`
	AgentID     string    `json:"agent_id"`
	Timestamp   time.Time `json:"timestamp"`
	ThreatType  string    `json:"threat_type"`
	Severity    string    `json:"severity"` // low, medium, high, critical
	FilePath    string    `json:"file_path"`
	Description string    `json:"description"`
	Hash        string    `json:"hash"`
}

// SystemStatus represents the current status of the system
type SystemStatus struct {
	ID        string    `json:"id"`
	AgentID   string    `json:"agent_id"`
	Timestamp time.Time `json:"timestamp"`
	Status    string    `json:"status"` // protected, unprotecting, scanning
	Uptime    string    `json:"uptime"`
	CPUUsage  float64   `json:"cpu_usage"`
	MemUsage  float64   `json:"mem_usage"`
	Version   string    `json:"version"`
}

// AgentStatus represents the status of the agent
type AgentStatus struct {
	ID          string    `json:"id"`
	AgentID     string    `json:"agent_id"`
	Timestamp   time.Time `json:"timestamp"`
	Version     string    `json:"version"`
	Status      string    `json:"status"` // running, stopped, error
	LastScan    time.Time `json:"last_scan"`
	TotalScans  int       `json:"total_scans"`
	ThreatsFound int      `json:"threats_found"`
	LastUpdate  time.Time `json:"last_update"`
}

// MetricsData represents collected metrics
type MetricsData struct {
	ID        string                 `json:"id"`
	AgentID   string                 `json:"agent_id"`
	Timestamp time.Time              `json:"timestamp"`
	Type      string                 `json:"type"` // cpu, memory, disk, network, etc.
	Data      map[string]interface{} `json:"data"`
}