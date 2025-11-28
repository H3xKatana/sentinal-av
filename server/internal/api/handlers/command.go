package handlers

import (
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/0xA1M/sentinel-server/internal/models"
	"github.com/gorilla/mux"
	"gorm.io/gorm"
)

// CommandService handles command-related operations
type CommandService struct {
	DB *gorm.DB
}

// NewCommandService creates a new command service
func NewCommandService(db *gorm.DB) *CommandService {
	return &CommandService{DB: db}
}

// Command represents a command sent from the server to an agent
type Command struct {
	ID        uint      `json:"id" gorm:"primaryKey"`
	AgentID   uint      `json:"agent_id" gorm:"index"`
	Command   string    `json:"command"`   // scan, update, etc.
	Status    string    `json:"status"`    // pending, completed, failed
	Params    string    `json:"params"`    // JSON string of command parameters
	CreatedAt time.Time `json:"created_at"`
	CompletedAt *time.Time `json:"completed_at,omitempty"`
}

// GetPendingCommandsHandler returns pending commands for an agent
func GetPendingCommandsHandler(svc *CommandService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		agentIDStr := r.URL.Query().Get("agent_id")
		if agentIDStr == "" {
			// In local setup without auth, we could potentially identify agent by other means
			// For now, let's allow agent identification by name or IP address as well
			http.Error(w, "Agent ID is required", http.StatusBadRequest)
			return
		}

		agentID, err := strconv.ParseUint(agentIDStr, 10, 32)
		if err != nil {
			http.Error(w, "Invalid Agent ID", http.StatusBadRequest)
			return
		}

		var commands []Command
		result := svc.DB.Where("agent_id = ? AND status = ?", uint(agentID), "pending").Find(&commands)
		if result.Error != nil {
			http.Error(w, "Failed to retrieve commands", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(commands)
	}
}

// UpdateCommandStatusHandler updates the status of a command
func UpdateCommandStatusHandler(svc *CommandService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		id, err := strconv.Atoi(vars["id"])
		if err != nil {
			http.Error(w, "Invalid command ID", http.StatusBadRequest)
			return
		}

		var req struct {
			Status string `json:"status"`
			Error  string `json:"error,omitempty"`
		}

		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}

		var command Command
		result := svc.DB.First(&command, id)
		if result.Error != nil {
			if result.Error == gorm.ErrRecordNotFound {
				http.Error(w, "Command not found", http.StatusNotFound)
				return
			}
			http.Error(w, "Failed to retrieve command", http.StatusInternalServerError)
			return
		}

		command.Status = req.Status
		if req.Status != "pending" {
			now := time.Now()
			command.CompletedAt = &now
		}

		result = svc.DB.Save(&command)
		if result.Error != nil {
			http.Error(w, "Failed to update command status", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(command)
	}
}

// CreateCommandHandler creates a new command for an agent
func CreateCommandHandler(svc *CommandService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			AgentID uint   `json:"agent_id"`
			Command string `json:"command"`
			Params  string `json:"params"`
		}

		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}

		// Verify agent exists
		var agent models.Agent
		result := svc.DB.First(&agent, req.AgentID)
		if result.Error != nil {
			if result.Error == gorm.ErrRecordNotFound {
				http.Error(w, "Agent not found", http.StatusNotFound)
				return
			}
			http.Error(w, "Failed to verify agent", http.StatusInternalServerError)
			return
		}

		command := Command{
			AgentID: req.AgentID,
			Command: req.Command,
			Status:  "pending",
			Params:  req.Params,
		}

		result = svc.DB.Create(&command)
		if result.Error != nil {
			http.Error(w, "Failed to create command", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(command)
	}
}