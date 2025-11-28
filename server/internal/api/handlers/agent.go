package handlers

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/0xA1M/sentinel-server/internal/api/utils"
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
			utils.SendErrorResponse(w, utils.NewAPIError("Failed to retrieve agents", http.StatusInternalServerError))
			return
		}

		utils.SendSuccessResponse(w, agents)
	}
}

// GetAgentHandler returns a specific agent by ID
func GetAgentHandler(svc *AgentService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		id, err := strconv.Atoi(vars["id"])
		if err != nil {
			utils.SendErrorResponse(w, utils.NewAPIError("Invalid agent ID", http.StatusBadRequest))
			return
		}

		var agent models.Agent
		result := svc.DB.First(&agent, id)
		if result.Error != nil {
			if result.Error == gorm.ErrRecordNotFound {
				utils.SendErrorResponse(w, utils.NewAPIError("Agent not found", http.StatusNotFound))
				return
			}
			utils.SendErrorResponse(w, utils.NewAPIError("Failed to retrieve agent", http.StatusInternalServerError))
			return
		}

		utils.SendSuccessResponse(w, agent)
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
			utils.SendErrorResponse(w, utils.NewAPIError("Invalid request body", http.StatusBadRequest))
			return
		}

		// Check if agent already exists based on name or public key
		var existingAgent models.Agent
		result := svc.DB.Where("name = ? OR public_key = ?", req.Name, req.PublicKey).First(&existingAgent)
		if result.Error == nil {
			// Agent already exists, return existing agent info
			utils.SendSuccessResponseWithMessage(w, "Agent already registered", map[string]interface{}{
				"agent_id": existingAgent.AgentID,
				"token":    "dummy-token", // In real implementation, generate a proper token
			})
			return
		} else if result.Error != gorm.ErrRecordNotFound {
			utils.SendErrorResponse(w, utils.NewAPIError("Database error", http.StatusInternalServerError))
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
			utils.SendErrorResponse(w, utils.NewAPIError("Failed to register agent", http.StatusInternalServerError))
			return
		}

		// Generate a unique agent ID based on the auto-increment ID
		agent.AgentID = generateAgentID(agent.ID)
		result = svc.DB.Save(&agent)
		if result.Error != nil {
			utils.SendErrorResponse(w, utils.NewAPIError("Failed to save agent ID", http.StatusInternalServerError))
			return
		}

		// Log agent registration
		log.Printf("Agent registered: ID=%s, Name=%s, Hostname=%s, Platform=%s, Version=%s, IP=%s",
			agent.AgentID, agent.Name, agent.Hostname, agent.Platform, agent.Version, agent.IPAddress)

		utils.SendSuccessResponseWithMessage(w, "Agent registered successfully", map[string]interface{}{
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
			utils.SendErrorResponse(w, utils.NewAPIError("Invalid agent ID", http.StatusBadRequest))
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
			utils.SendErrorResponse(w, utils.NewAPIError("Invalid request body", http.StatusBadRequest))
			return
		}

		var agent models.Agent
		result := svc.DB.First(&agent, id)
		if result.Error != nil {
			if result.Error == gorm.ErrRecordNotFound {
				utils.SendErrorResponse(w, utils.NewAPIError("Agent not found", http.StatusNotFound))
				return
			}
			utils.SendErrorResponse(w, utils.NewAPIError("Failed to retrieve agent", http.StatusInternalServerError))
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
			utils.SendErrorResponse(w, utils.NewAPIError("Failed to update agent", http.StatusInternalServerError))
			return
		}

		utils.SendSuccessResponse(w, agent)
	}
}

// DeleteAgentHandler deletes an agent
func DeleteAgentHandler(svc *AgentService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		id, err := strconv.Atoi(vars["id"])
		if err != nil {
			utils.SendErrorResponse(w, utils.NewAPIError("Invalid agent ID", http.StatusBadRequest))
			return
		}

		result := svc.DB.Delete(&models.Agent{}, id)
		if result.Error != nil {
			utils.SendErrorResponse(w, utils.NewAPIError("Failed to delete agent", http.StatusInternalServerError))
			return
		}

		utils.SendSuccessResponseWithMessage(w, "Agent deleted successfully", nil)
	}
}

// QuarantineAgentHandler quarantines an agent
func QuarantineAgentHandler(svc *AgentService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		id, err := strconv.Atoi(vars["id"])
		if err != nil {
			utils.SendErrorResponse(w, utils.NewAPIError("Invalid agent ID", http.StatusBadRequest))
			return
		}

		var agent models.Agent
		result := svc.DB.First(&agent, id)
		if result.Error != nil {
			if result.Error == gorm.ErrRecordNotFound {
				utils.SendErrorResponse(w, utils.NewAPIError("Agent not found", http.StatusNotFound))
				return
			}
			utils.SendErrorResponse(w, utils.NewAPIError("Failed to retrieve agent", http.StatusInternalServerError))
			return
		}

		agent.Quarantine = true
		agent.UpdatedAt = time.Now()

		result = svc.DB.Save(&agent)
		if result.Error != nil {
			utils.SendErrorResponse(w, utils.NewAPIError("Failed to quarantine agent", http.StatusInternalServerError))
			return
		}

		utils.SendSuccessResponse(w, agent)
	}
}

// UnquarantineAgentHandler removes quarantine from an agent
func UnquarantineAgentHandler(svc *AgentService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		id, err := strconv.Atoi(vars["id"])
		if err != nil {
			utils.SendErrorResponse(w, utils.NewAPIError("Invalid agent ID", http.StatusBadRequest))
			return
		}

		var agent models.Agent
		result := svc.DB.First(&agent, id)
		if result.Error != nil {
			if result.Error == gorm.ErrRecordNotFound {
				utils.SendErrorResponse(w, utils.NewAPIError("Agent not found", http.StatusNotFound))
				return
			}
			utils.SendErrorResponse(w, utils.NewAPIError("Failed to retrieve agent", http.StatusInternalServerError))
			return
		}

		agent.Quarantine = false
		agent.UpdatedAt = time.Now()

		result = svc.DB.Save(&agent)
		if result.Error != nil {
			utils.SendErrorResponse(w, utils.NewAPIError("Failed to unquarantine agent", http.StatusInternalServerError))
			return
		}

		utils.SendSuccessResponse(w, agent)
	}
}

// GetAgentScansHandler returns scans for a specific agent
func GetAgentScansHandler(svc *ScanService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		agentID, err := strconv.Atoi(vars["id"])
		if err != nil {
			utils.SendErrorResponse(w, utils.NewAPIError("Invalid agent ID", http.StatusBadRequest))
			return
		}

		var scanResults []models.ScanResult
		result := svc.DB.Where("agent_id = ?", uint(agentID)).Preload("Threats").Order("scan_time DESC").Find(&scanResults)
		if result.Error != nil {
			utils.SendErrorResponse(w, utils.NewAPIError("Failed to retrieve agent scan results", http.StatusInternalServerError))
			return
		}

		utils.SendSuccessResponse(w, scanResults)
	}
}

// GetAgentThreatsHandler returns threats for a specific agent
func GetAgentThreatsHandler(svc *ThreatService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		agentID, err := strconv.Atoi(vars["id"])
		if err != nil {
			utils.SendErrorResponse(w, utils.NewAPIError("Invalid agent ID", http.StatusBadRequest))
			return
		}

		var threats []models.Threat
		result := svc.DB.Where("agent_id = ?", uint(agentID)).Preload("ScanResult").Order("created_at DESC").Find(&threats)
		if result.Error != nil {
			utils.SendErrorResponse(w, utils.NewAPIError("Failed to retrieve agent threats", http.StatusInternalServerError))
			return
		}

		utils.SendSuccessResponse(w, threats)
	}
}

// generateAgentID creates a unique ID for an agent
func generateAgentID(id uint) string {
	// Format: agent-<timestamp>-<auto-increment-id>
	timestamp := time.Now().Unix()
	return fmt.Sprintf("agent-%d-%d", timestamp, id)
}

// GetAgentsStatusHandler returns the status of all agents
func GetAgentsStatusHandler(svc *AgentService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var agents []models.Agent
		result := svc.DB.Find(&agents)
		if result.Error != nil {
			utils.SendErrorResponse(w, utils.NewAPIError("Failed to retrieve agents", http.StatusInternalServerError))
			return
		}

		type AgentStatus struct {
			ID          uint      `json:"id"`
			Name        string    `json:"name"`
			AgentID     string    `json:"agent_id"`
			IsActive    bool      `json:"is_active"`
			Quarantine  bool      `json:"quarantine"`
			LastSeen    time.Time `json:"last_seen"`
			Platform    string    `json:"platform"`
			IPAddress   string    `json:"ip_address"`
			IsOnline    bool      `json:"is_online"` // Agent is considered online if last seen within 5 minutes
		}

		now := time.Now()
		statuses := make([]AgentStatus, len(agents))
		for i, agent := range agents {
			isOnline := false
			if agent.LastSeen != nil {
				// Consider agent online if it was seen in the last 5 minutes
				isOnline = now.Sub(*agent.LastSeen) < 5*time.Minute
			}

			statuses[i] = AgentStatus{
				ID:          agent.ID,
				Name:        agent.Name,
				AgentID:     agent.AgentID,
				IsActive:    agent.IsActive,
				Quarantine:  agent.Quarantine,
				LastSeen:    *agent.LastSeen,
				Platform:    agent.Platform,
				IPAddress:   agent.IPAddress,
				IsOnline:    isOnline,
			}
		}

		utils.SendSuccessResponse(w, statuses)
	}
}