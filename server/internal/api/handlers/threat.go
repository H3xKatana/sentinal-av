package handlers

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/0xA1M/sentinel-server/internal/models"
	"github.com/gorilla/mux"
	"gorm.io/gorm"
)

// ThreatService handles threat-related operations
type ThreatService struct {
	DB *gorm.DB
}

// NewThreatService creates a new threat service
func NewThreatService(db *gorm.DB) *ThreatService {
	return &ThreatService{DB: db}
}

// GetThreatsHandler returns all threats
func GetThreatsHandler(svc *ThreatService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var threats []models.Threat
		result := svc.DB.Preload("Agent").Preload("ScanResult").Find(&threats)
		if result.Error != nil {
			http.Error(w, "Failed to retrieve threats", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(threats)
	}
}

// GetThreatHandler returns a specific threat by ID
func GetThreatHandler(svc *ThreatService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		id, err := strconv.Atoi(vars["id"])
		if err != nil {
			http.Error(w, "Invalid threat ID", http.StatusBadRequest)
			return
		}

		var threat models.Threat
		result := svc.DB.Preload("Agent").Preload("ScanResult").First(&threat, id)
		if result.Error != nil {
			if result.Error == gorm.ErrRecordNotFound {
				http.Error(w, "Threat not found", http.StatusNotFound)
				return
			}
			http.Error(w, "Failed to retrieve threat", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(threat)
	}
}

// CreateThreatHandler creates a new threat
func CreateThreatHandler(svc *ThreatService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req models.Threat

		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}

		// Validate required fields
		if req.FilePath == "" || req.ThreatType == "" {
			http.Error(w, "FilePath and ThreatType are required", http.StatusBadRequest)
			return
		}

		// Create threat
		threat := models.Threat{
			AgentID:      req.AgentID,
			FilePath:     req.FilePath,
			ThreatType:   req.ThreatType,
			ThreatName:   req.ThreatName,
			Severity:     req.Severity,
			ActionTaken:  req.ActionTaken,
			CreatedAt:    req.CreatedAt,
		}

		// If AgentID is provided, verify agent exists
		if req.AgentID != nil {
			var agent models.Agent
			result := svc.DB.First(&agent, *req.AgentID)
			if result.Error != nil {
				if result.Error == gorm.ErrRecordNotFound {
					http.Error(w, "Agent not found", http.StatusNotFound)
					return
				}
				http.Error(w, "Failed to verify agent", http.StatusInternalServerError)
				return
			}
		}

		result := svc.DB.Create(&threat)
		if result.Error != nil {
			http.Error(w, "Failed to create threat", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(threat)
	}
}

// UpdateThreatHandler updates an existing threat
func UpdateThreatHandler(svc *ThreatService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		id, err := strconv.Atoi(vars["id"])
		if err != nil {
			http.Error(w, "Invalid threat ID", http.StatusBadRequest)
			return
		}

		var req struct {
			FilePath    string `json:"file_path"`
			ThreatType  string `json:"threat_type"`
			ThreatName  string `json:"threat_name"`
			Severity    string `json:"severity"`
			ActionTaken string `json:"action_taken"`
		}

		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}

		var threat models.Threat
		result := svc.DB.First(&threat, id)
		if result.Error != nil {
			if result.Error == gorm.ErrRecordNotFound {
				http.Error(w, "Threat not found", http.StatusNotFound)
				return
			}
			http.Error(w, "Failed to retrieve threat", http.StatusInternalServerError)
			return
		}

		// Update threat fields
		threat.FilePath = req.FilePath
		threat.ThreatType = req.ThreatType
		threat.ThreatName = req.ThreatName
		threat.Severity = req.Severity
		threat.ActionTaken = req.ActionTaken

		result = svc.DB.Save(&threat)
		if result.Error != nil {
			http.Error(w, "Failed to update threat", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(threat)
	}
}

// DeleteThreatHandler deletes a threat
func DeleteThreatHandler(svc *ThreatService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		id, err := strconv.Atoi(vars["id"])
		if err != nil {
			http.Error(w, "Invalid threat ID", http.StatusBadRequest)
			return
		}

		result := svc.DB.Delete(&models.Threat{}, id)
		if result.Error != nil {
			http.Error(w, "Failed to delete threat", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "success"})
	}
}

// GetThreatsBySeverityHandler returns threats filtered by severity
func GetThreatsBySeverityHandler(svc *ThreatService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		severity := vars["severity"]

		var threats []models.Threat
		result := svc.DB.Where("severity = ?", severity).Preload("Agent").Preload("ScanResult").Find(&threats)
		if result.Error != nil {
			http.Error(w, "Failed to retrieve threats by severity", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(threats)
	}
}

// GetThreatsByAgentHandler returns threats for a specific agent
func GetThreatsByAgentHandler(svc *ThreatService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		agentID, err := strconv.Atoi(vars["agentId"])
		if err != nil {
			http.Error(w, "Invalid agent ID", http.StatusBadRequest)
			return
		}

		var threats []models.Threat
		result := svc.DB.Where("agent_id = ?", uint(agentID)).Preload("ScanResult").Find(&threats)
		if result.Error != nil {
			http.Error(w, "Failed to retrieve threats", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(threats)
	}
}