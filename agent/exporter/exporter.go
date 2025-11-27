package exporter

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"
)

// HTTPExporter implements the Exporter interface using HTTP to send data to the server
type HTTPExporter struct {
	config   Config
	client   *http.Client
	started  bool
	shutdown chan struct{}
}

// NewHTTPExporter creates a new HTTP exporter
func NewHTTPExporter(config Config) *HTTPExporter {
	if config.Timeout == 0 {
		config.Timeout = 30 * time.Second
	}
	if config.RetryCount == 0 {
		config.RetryCount = 3
	}
	if config.RetryDelay == 0 {
		config.RetryDelay = 5 * time.Second
	}
	if config.MaxBatchSize == 0 {
		config.MaxBatchSize = 100
	}

	return &HTTPExporter{
		config:   config,
		client:   &http.Client{Timeout: config.Timeout},
		shutdown: make(chan struct{}),
	}
}

// Export sends data to the server backend
func (he *HTTPExporter) Export(ctx context.Context, data Data) error {
	if !he.started {
		return fmt.Errorf("exporter not started")
	}

	// Add agent ID if not present
	if data.AgentID == "" {
		data.AgentID = he.config.AgentID
	}

	// Add timestamp if not present
	if data.Timestamp.IsZero() {
		data.Timestamp = time.Now()
	}

	return he.sendData(ctx, data)
}

// ExportBatch sends multiple data items to the server backend
func (he *HTTPExporter) ExportBatch(ctx context.Context, data []Data) error {
	if !he.started {
		return fmt.Errorf("exporter not started")
	}

	if len(data) == 0 {
		return nil
	}

	// Add agent ID and timestamp to each data item if not present
	for i := range data {
		if data[i].AgentID == "" {
			data[i].AgentID = he.config.AgentID
		}
		if data[i].Timestamp.IsZero() {
			data[i].Timestamp = time.Now()
		}
	}

	// If the batch is too large, send in chunks
	if len(data) > he.config.MaxBatchSize {
		for i := 0; i < len(data); i += he.config.MaxBatchSize {
			end := i + he.config.MaxBatchSize
			if end > len(data) {
				end = len(data)
			}
			if err := he.sendBatch(ctx, data[i:end]); err != nil {
				return err
			}
		}
		return nil
	}

	return he.sendBatch(ctx, data)
}

// sendBatch sends a batch of data items to the server
func (he *HTTPExporter) sendBatch(ctx context.Context, data []Data) error {
	// Create batch payload
	payload := map[string]interface{}{
		"agent_id": he.config.AgentID,
		"timestamp": time.Now().Format(time.RFC3339),
		"data":      data,
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal batch data: %v", err)
	}

	return he.doRequest(ctx, jsonData)
}

// sendData sends a single data item to the server
func (he *HTTPExporter) sendData(ctx context.Context, data Data) error {
	jsonData, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("failed to marshal data: %v", err)
	}

	return he.doRequest(ctx, jsonData)
}

// doRequest performs the actual HTTP request to the server
func (he *HTTPExporter) doRequest(ctx context.Context, jsonData []byte) error {
	var lastErr error

	for i := 0; i <= he.config.RetryCount; i++ {
		if i > 0 {
			log.Printf("Retrying request, attempt %d/%d", i, he.config.RetryCount+1)
			time.Sleep(he.config.RetryDelay)
		}

		req, err := http.NewRequestWithContext(ctx, "POST", he.config.ServerURL, bytes.NewBuffer(jsonData))
		if err != nil {
			lastErr = fmt.Errorf("failed to create request: %v", err)
			continue
		}

		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("User-Agent", "Sentinel-Agent-Exporter/1.0")

		resp, err := he.client.Do(req)
		if err != nil {
			lastErr = fmt.Errorf("request failed: %v", err)
			continue
		}

		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()

		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			log.Printf("Successfully exported data, status: %d", resp.StatusCode)
			return nil
		} else {
			lastErr = fmt.Errorf("export failed with status %d: %s", resp.StatusCode, string(body))
		}
	}

	return fmt.Errorf("failed to export data after %d retries: %v", he.config.RetryCount, lastErr)
}

// Start initializes the exporter
func (he *HTTPExporter) Start() error {
	he.started = true
	return nil
}

// Stop shuts down the exporter gracefully
func (he *HTTPExporter) Stop() error {
	if !he.started {
		return fmt.Errorf("exporter not started")
	}

	he.started = false
	close(he.shutdown)
	he.client.CloseIdleConnections()

	return nil
}

// HealthCheck checks if the exporter is healthy
func (he *HTTPExporter) HealthCheck(ctx context.Context) error {
	// Create a simple health check request
	payload := map[string]interface{}{
		"type":      "health_check",
		"agent_id":  he.config.AgentID,
		"timestamp": time.Now(),
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal health check data: %v", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", he.config.ServerURL, bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to create health check request: %v", err)
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := he.client.Do(req)
	if err != nil {
		return fmt.Errorf("health check request failed: %v", err)
	}
	resp.Body.Close()

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil
	}

	return fmt.Errorf("health check failed with status: %d", resp.StatusCode)
}

// SetConfig updates the exporter configuration
func (he *HTTPExporter) SetConfig(config Config) {
	he.config = config

	// Update the HTTP client if timeout changed
	if he.config.Timeout != 0 {
		he.client = &http.Client{Timeout: config.Timeout}
	}
}