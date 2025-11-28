package common

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"
)

// Alert represents an alert to be sent to the server
type Alert struct {
	Source      string      `json:"source"`
	AlertType   string      `json:"alert_type"`
	Description string      `json:"description"`
	Data        interface{} `json:"data"`
}

// AlertClient handles communication with the server
type AlertClient struct {
	ServerURL string
	HTTPClient *http.Client
}

// NewAlertClient creates a new client for sending alerts to the server
func NewAlertClient(serverURL string) *AlertClient {
	return &AlertClient{
		ServerURL: serverURL,
		HTTPClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// SendAlert sends an alert to the server
func (ac *AlertClient) SendAlert(alert Alert) error {
	jsonData, err := json.Marshal(alert)
	if err != nil {
		return fmt.Errorf("failed to marshal alert: %v", err)
	}

	resp, err := ac.HTTPClient.Post(
		ac.ServerURL+"/alert", // ServerURL is expected to include the base path (e.g., http://localhost:3000/api), so this will be http://localhost:3000/api/alert
		"application/json",
		bytes.NewBuffer(jsonData),
	)
	if err != nil {
		return fmt.Errorf("failed to send alert: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("server returned non-OK status: %d", resp.StatusCode)
	}

	log.Printf("Alert sent successfully: %s - %s", alert.AlertType, alert.Description)
	return nil
}