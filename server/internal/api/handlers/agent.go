package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/0xA1M/sentinel-server/internal/models"
	"github.com/gorilla/mux"
	"gorm.io/gorm"
)

// AgentService handles agent-related operations
type AgentService struct {
	DB *gorm.DB
}

// NewAgentService creates a new agent service
func NewAgentService(db *gorm.DB) *AgentService {
	return &AgentService{DB: db}
}

// GetAgentsHandler returns all agents
func GetAgentsHandler(svc *AgentService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var agents []models.Agent
		result := svc.DB.Find(&agents)
		if result.Error != nil {
			http.Error(w, "Failed to retrieve agents", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(agents)
	}
}

// GetAgentHandler returns a specific agent by ID
func GetAgentHandler(svc *AgentService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		id, err := strconv.Atoi(vars["id"])
		if err != nil {
			http.Error(w, "Invalid agent ID", http.StatusBadRequest)
			return
		}

		var agent models.Agent
		result := svc.DB.First(&agent, id)
		if result.Error != nil {
			if result.Error == gorm.ErrRecordNotFound {
				http.Error(w, "Agent not found", http.StatusNotFound)
				return
			}
			http.Error(w, "Failed to retrieve agent", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(agent)
	}
}

// CreateAgentHandler creates a new agent
func CreateAgentHandler(svc *AgentService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Name      string `json:"name"`
			Hostname  string `json:"hostname"`
			Platform  string `json:"platform"`
			Version   string `json:"version"`
			IPAddress string `json:"ip_address"`
			PublicKey string `json:"public_key"`
		}

		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}

		// Check if agent already exists based on name or public key
		var existingAgent models.Agent
		result := svc.DB.Where("name = ? OR public_key = ?", req.Name, req.PublicKey).First(&existingAgent)
		if result.Error == nil {
			// Agent already exists, return existing agent info
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{
				"agent_id": existingAgent.AgentID,
				"token":    "dummy-token", // In real implementation, generate a proper token
			})
			return
		} else if result.Error != gorm.ErrRecordNotFound {
			http.Error(w, "Database error", http.StatusInternalServerError)
			return
		}

		// Create new agent
		agent := models.Agent{
			Name:         req.Name,
			Hostname:     req.Hostname,
			Platform:     req.Platform,
			Version:      req.Version,
			IPAddress:    req.IPAddress,
			PublicKey:    req.PublicKey,
			LastSeen:     &[]time.Time{time.Now()}[0], // Using this syntax to get address of time
			IsActive:     true,
			Quarantine:   false,
			RegisteredAt: time.Now(),
		}

		result = svc.DB.Create(&agent)
		if result.Error != nil {
			http.Error(w, "Failed to register agent", http.StatusInternalServerError)
			return
		}

		// Generate a unique agent ID based on the auto-increment ID
		agent.AgentID = generateAgentID(agent.ID)
		result = svc.DB.Save(&agent)
		if result.Error != nil {
			http.Error(w, "Failed to save agent ID", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"agent_id": agent.AgentID,
			"token":    "dummy-token", // In real implementation, generate a proper token
		})
	}
}

// UpdateAgentHandler updates an existing agent
func UpdateAgentHandler(svc *AgentService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		id, err := strconv.Atoi(vars["id"])
		if err != nil {
			http.Error(w, "Invalid agent ID", http.StatusBadRequest)
			return
		}

		var req struct {
			Name      string `json:"name"`
			Hostname  string `json:"hostname"`
			Version   string `json:"version"`
			IPAddress string `json:"ip_address"`
			IsActive  *bool  `json:"is_active"`
		}

		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}

		var agent models.Agent
		result := svc.DB.First(&agent, id)
		if result.Error != nil {
			if result.Error == gorm.ErrRecordNotFound {
				http.Error(w, "Agent not found", http.StatusNotFound)
				return
			}
			http.Error(w, "Failed to retrieve agent", http.StatusInternalServerError)
			return
		}

		// Update agent fields
		agent.Name = req.Name
		agent.Hostname = req.Hostname
		agent.Version = req.Version
		agent.IPAddress = req.IPAddress
		if req.IsActive != nil {
			agent.IsActive = *req.IsActive
		}
		agent.UpdatedAt = time.Now()

		result = svc.DB.Save(&agent)
		if result.Error != nil {
			http.Error(w, "Failed to update agent", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(agent)
	}
}

// DeleteAgentHandler deletes an agent
func DeleteAgentHandler(svc *AgentService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		id, err := strconv.Atoi(vars["id"])
		if err != nil {
			http.Error(w, "Invalid agent ID", http.StatusBadRequest)
			return
		}

		result := svc.DB.Delete(&models.Agent{}, id)
		if result.Error != nil {
			http.Error(w, "Failed to delete agent", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "success"})
	}
}

// QuarantineAgentHandler quarantines an agent
func QuarantineAgentHandler(svc *AgentService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		id, err := strconv.Atoi(vars["id"])
		if err != nil {
			http.Error(w, "Invalid agent ID", http.StatusBadRequest)
			return
		}

		var agent models.Agent
		result := svc.DB.First(&agent, id)
		if result.Error != nil {
			if result.Error == gorm.ErrRecordNotFound {
				http.Error(w, "Agent not found", http.StatusNotFound)
				return
			}
			http.Error(w, "Failed to retrieve agent", http.StatusInternalServerError)
			return
		}

		agent.Quarantine = true
		agent.UpdatedAt = time.Now()

		result = svc.DB.Save(&agent)
		if result.Error != nil {
			http.Error(w, "Failed to quarantine agent", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(agent)
	}
}

// UnquarantineAgentHandler removes quarantine from an agent
func UnquarantineAgentHandler(svc *AgentService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		id, err := strconv.Atoi(vars["id"])
		if err != nil {
			http.Error(w, "Invalid agent ID", http.StatusBadRequest)
			return
		}

		var agent models.Agent
		result := svc.DB.First(&agent, id)
		if result.Error != nil {
			if result.Error == gorm.ErrRecordNotFound {
				http.Error(w, "Agent not found", http.StatusNotFound)
				return
			}
			http.Error(w, "Failed to retrieve agent", http.StatusInternalServerError)
			return
		}

		agent.Quarantine = false
		agent.UpdatedAt = time.Now()

		result = svc.DB.Save(&agent)
		if result.Error != nil {
			http.Error(w, "Failed to unquarantine agent", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(agent)
	}
}

// generateAgentID creates a unique ID for an agent
func generateAgentID(id uint) string {
	// Format: agent-<timestamp>-<auto-increment-id>
	timestamp := time.Now().Unix()
	return fmt.Sprintf("agent-%d-%d", timestamp, id)
}
