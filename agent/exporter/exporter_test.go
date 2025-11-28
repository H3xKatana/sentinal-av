package exporter

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestHTTPExporter(t *testing.T) {
	// Create a test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify the request is properly formatted
		var data map[string]interface{}
		err := json.NewDecoder(r.Body).Decode(&data)
		if err != nil {
			t.Errorf("Failed to decode request body: %v", err)
		}
		
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	// Create exporter config
	config := Config{
		ServerURL:  server.URL,
		AgentID:    "test-agent",
		Timeout:    10 * time.Second,
		RetryCount: 1,
		RetryDelay: time.Second,
	}

	// Create exporter
	exporter := NewHTTPExporter(config)
	err := exporter.Start()
	if err != nil {
		t.Fatalf("Failed to start exporter: %v", err)
	}
	defer exporter.Stop()

	// Test exporting data
	testData := Data{
		ID:        "test-123",
		Type:      ScanResultType,
		Timestamp: time.Now(),
		Payload: map[string]interface{}{
			"test": "value",
		},
		AgentID: "test-agent",
	}

	ctx := context.Background()
	err = exporter.Export(ctx, testData)
	if err != nil {
		t.Errorf("Failed to export data: %v", err)
	}

	// Test exporting batch data
	testBatch := []Data{testData, testData}
	err = exporter.ExportBatch(ctx, testBatch)
	if err != nil {
		t.Errorf("Failed to export batch data: %v", err)
	}

	// Test health check
	err = exporter.HealthCheck(ctx)
	if err != nil {
		t.Errorf("Health check failed: %v", err)
	}
}

func TestConfig(t *testing.T) {
	// Test default config values
	config := Config{}

	if config.Timeout != 0 {
		t.Errorf("Expected default timeout to be 0, got %v", config.Timeout)
	}

	// These will be set by the NewHTTPExporter function
	exporter := NewHTTPExporter(config)
	if exporter.config.Timeout == 0 {
		t.Errorf("Expected timeout to be set to default 30s, got %v", exporter.config.Timeout)
	}
}