package common

import (
	"testing"
	"time"
)

func TestScanResult(t *testing.T) {
	scanResult := ScanResult{
		ID:          "test-123",
		AgentID:     "agent-47",
		Timestamp:   time.Now(),
		ScannedPath: "/tmp/test",
		Infected:    []string{"/tmp/malware.exe"},
		ScanTime:    "1m20s",
	}

	if scanResult.ID != "test-123" {
		t.Errorf("Expected ID 'test-123', got '%s'", scanResult.ID)
	}

	if len(scanResult.Infected) != 1 {
		t.Errorf("Expected 1 infected file, got %d", len(scanResult.Infected))
	}
}

func TestThreatReport(t *testing.T) {
	threatReport := ThreatReport{
		ID:          "threat-123",
		AgentID:     "agent-47",
		Timestamp:   time.Now(),
		ThreatType:  "virus",
		Severity:    "high",
		FilePath:    "/tmp/malware.exe",
		Description: "Test malware",
		Hash:        "abc123",
	}

	if threatReport.ThreatType != "virus" {
		t.Errorf("Expected threat type 'virus', got '%s'", threatReport.ThreatType)
	}

	if threatReport.Severity != "high" {
		t.Errorf("Expected severity 'high', got '%s'", threatReport.Severity)
	}
}

func TestSystemStatus(t *testing.T) {
	status := SystemStatus{
		ID:        "status-123",
		AgentID:   "agent-47",
		Timestamp: time.Now(),
		Status:    "protected",
		Uptime:    "2h30m",
		CPUUsage:  15.5,
		MemUsage:  45.2,
		Version:   "1.0.0",
	}

	if status.Status != "protected" {
		t.Errorf("Expected status 'protected', got '%s'", status.Status)
	}

	if status.CPUUsage != 15.5 {
		t.Errorf("Expected CPU usage 15.5, got %f", status.CPUUsage)
	}
}

func TestAgentStatus(t *testing.T) {
	status := AgentStatus{
		ID:         "agent-status-123",
		AgentID:    "agent-47",
		Timestamp:  time.Now(),
		Version:    "1.0.0",
		Status:     "running",
		LastScan:   time.Now().Add(-1 * time.Hour),
		TotalScans: 10,
		ThreatsFound: 2,
	}

	if status.Status != "running" {
		t.Errorf("Expected status 'running', got '%s'", status.Status)
	}

	if status.TotalScans != 10 {
		t.Errorf("Expected total scans 10, got %d", status.TotalScans)
	}
}

func TestMetricsData(t *testing.T) {
	metrics := MetricsData{
		ID:        "metrics-123",
		AgentID:   "agent-47",
		Timestamp: time.Now(),
		Type:      "cpu",
		Data: map[string]interface{}{
			"usage": 15.5,
			"cores": 4,
		},
	}

	if metrics.Type != "cpu" {
		t.Errorf("Expected metrics type 'cpu', got '%s'", metrics.Type)
	}

	if len(metrics.Data) != 2 {
		t.Errorf("Expected 2 data entries, got %d", len(metrics.Data))
	}
}