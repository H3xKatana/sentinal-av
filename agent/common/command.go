package common

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"
)

// Command represents a command from the server to the agent
type Command struct {
	ID          uint      `json:"id"`
	AgentID     uint      `json:"agent_id"`
	Command     string    `json:"command"`      // scan, update, etc.
	Status      string    `json:"status"`       // pending, completed, failed
	Params      string    `json:"params"`       // JSON string of command parameters
	CreatedAt   time.Time `json:"created_at"`
	CompletedAt *time.Time `json:"completed_at,omitempty"`
}

// CommandClient handles communication with the server for command operations
type CommandClient struct {
	ServerURL  string
	HTTPClient *http.Client
	AgentID    string // Agent name/ID
}

// NewCommandClient creates a new client for handling commands from the server
func NewCommandClient(serverURL, agentID string) *CommandClient {
	return &CommandClient{
		ServerURL: serverURL,
		HTTPClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		AgentID: agentID,
	}
}

// GetPendingCommandsByAgentID fetches pending commands for a specific agent ID
func (cc *CommandClient) GetPendingCommandsByAgentID(agentID uint) ([]Command, error) {
	url := fmt.Sprintf("%s?agent_id=%d", cc.ServerURL, agentID)

	resp, err := cc.HTTPClient.Get(url)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch commands: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("server returned non-OK status: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %v", err)
	}

	var commands []Command
	if err := json.Unmarshal(body, &commands); err != nil {
		return nil, fmt.Errorf("failed to unmarshal commands: %v", err)
	}

	return commands, nil
}

// GetPendingCommands fetches pending commands for this agent (placeholder)
func (cc *CommandClient) GetPendingCommands() ([]Command, error) {
	// This is a placeholder that defaults to agent ID 1
	// In a real implementation, there would be a way to identify the requesting agent
	return cc.GetPendingCommandsByAgentID(1)
}

// UpdateCommandStatus updates the status of a command
func (cc *CommandClient) UpdateCommandStatus(commandID uint, status string, errorMsg string) error {
	payload := map[string]string{
		"status": status,
	}
	if errorMsg != "" {
		payload["error"] = errorMsg
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal status update: %v", err)
	}

	url := fmt.Sprintf("%s/%d", cc.ServerURL, commandID)
	req, err := http.NewRequest("PUT", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := cc.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to update command status: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("server returned non-OK status: %d", resp.StatusCode)
	}

	log.Printf("Command status updated: ID=%d, Status=%s", commandID, status)
	return nil
}