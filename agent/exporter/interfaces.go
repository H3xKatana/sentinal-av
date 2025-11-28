package exporter

import (
	"context"
	"time"
)

// DataType defines the types of data that can be exported
type DataType string

const (
	ScanResultType    DataType = "scan_result"
	ThreatReportType  DataType = "threat_report"
	SystemStatusType  DataType = "system_status"
	AgentStatusType   DataType = "agent_status"
	MetricDataType    DataType = "metric_data"
)

// Data represents the data to be exported
type Data struct {
	ID        string                 `json:"id"`
	Type      DataType               `json:"type"`
	Timestamp time.Time              `json:"timestamp"`
	Payload   map[string]interface{} `json:"payload"`
	AgentID   string                 `json:"agent_id"`
}

// Exporter defines the interface for exporting data to the server backend
type Exporter interface {
	// Export sends data to the server backend
	Export(ctx context.Context, data Data) error
	
	// ExportBatch sends multiple data items to the server backend
	ExportBatch(ctx context.Context, data []Data) error
	
	// Start initializes the exporter
	Start() error
	
	// Stop shuts down the exporter gracefully
	Stop() error
	
	// HealthCheck checks if the exporter is healthy
	HealthCheck(ctx context.Context) error
	
	// SetConfig updates the exporter configuration
	SetConfig(config Config)
}

// Config holds configuration for the exporter
type Config struct {
	ServerURL    string        `json:"server_url"`
	AgentID      string        `json:"agent_id"`
	Timeout      time.Duration `json:"timeout"`
	RetryCount   int           `json:"retry_count"`
	RetryDelay   time.Duration `json:"retry_delay"`
	MaxBatchSize int           `json:"max_batch_size"`
}