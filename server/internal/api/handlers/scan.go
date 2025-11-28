package handlers

import (
	"encoding/json"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/0xA1M/sentinel-server/internal/models"
	"github.com/gorilla/mux"
	"gorm.io/gorm"
)

// ScanService handles scan-related operations
type ScanService struct {
	DB *gorm.DB
}

// NewScanService creates a new scan service
func NewScanService(db *gorm.DB) *ScanService {
	return &ScanService{DB: db}
}

// GetScanResultsHandler returns all scan results
func GetScanResultsHandler(svc *ScanService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var scanResults []models.ScanResult
		result := svc.DB.Preload("Agent").Find(&scanResults)
		if result.Error != nil {
			http.Error(w, "Failed to retrieve scan results", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(scanResults)
	}
}

// GetScanResultHandler returns a specific scan result by ID
func GetScanResultHandler(svc *ScanService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		id, err := strconv.Atoi(vars["id"])
		if err != nil {
			http.Error(w, "Invalid scan result ID", http.StatusBadRequest)
			return
		}

		var scanResult models.ScanResult
		result := svc.DB.Preload("Agent").Preload("Threats").First(&scanResult, id)
		if result.Error != nil {
			if result.Error == gorm.ErrRecordNotFound {
				http.Error(w, "Scan result not found", http.StatusNotFound)
				return
			}
			http.Error(w, "Failed to retrieve scan result", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(scanResult)
	}
}

// CreateScanResultHandler creates a new scan result
func CreateScanResultHandler(svc *ScanService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			AgentID   uint     `json:"agent_id"`
			ScanType  string   `json:"scan_type"`
			FilePaths []string `json:"file_paths"`
			Threats   []struct {
				FilePath   string `json:"file_path"`
				ThreatType string `json:"threat_type"`
				ThreatName string `json:"threat_name"`
				Severity   string `json:"severity"`
			} `json:"threats"`
			Status string `json:"status"`
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

		// Create scan result
		scanResult := models.ScanResult{
			AgentID:   req.AgentID,
			ScanType:  req.ScanType,
			FilePaths: req.FilePaths,
			ScanTime:  time.Now(),
			Status:    req.Status,
		}

		result = svc.DB.Create(&scanResult)
		if result.Error != nil {
			http.Error(w, "Failed to create scan result", http.StatusInternalServerError)
			return
		}

		// Create threat records if any
		for _, threat := range req.Threats {
			scanResultID := scanResult.ID
			threatRecord := models.Threat{
				ScanResultID: &scanResultID,
				FilePath:     threat.FilePath,
				ThreatType:   threat.ThreatType,
				ThreatName:   threat.ThreatName,
				Severity:     threat.Severity,
				CreatedAt:    time.Now(),
			}
			svc.DB.Create(&threatRecord)
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(scanResult)
	}
}

// GetScanThreatsHandler returns threats from a specific scan
func GetScanThreatsHandler(svc *ScanService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		id, err := strconv.Atoi(vars["id"])
		if err != nil {
			http.Error(w, "Invalid scan result ID", http.StatusBadRequest)
			return
		}

		var threats []models.Threat
		result := svc.DB.Where("scan_result_id = ?", id).Find(&threats)
		if result.Error != nil {
			http.Error(w, "Failed to retrieve scan threats", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(threats)
	}
}

// TriggerScanRequest represents the request to trigger a scan on an agent
type TriggerScanRequest struct {
	AgentID    uint   `json:"agent_id"`
	ScanType   string `json:"scan_type"`   // full, quick, custom
	TargetPath string `json:"target_path"` // optional path to scan
}

// TriggerScanHandler handles requests to trigger a scan on an agent
func TriggerScanHandler(svc *ScanService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req TriggerScanRequest

		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}

		// Validate required fields
		if req.AgentID == 0 {
			http.Error(w, "AgentID is required", http.StatusBadRequest)
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

		// Log scan trigger
		log.Printf("Scan triggered: AgentID=%d, AgentName=%s, ScanType=%s, TargetPath=%s",
			req.AgentID, agent.Name, req.ScanType, req.TargetPath)

		// In a real implementation, we would send a command to the agent to initiate the scan
		// This might involve:
		// 1. Adding the scan command to a queue
		// 2. Using a pub/sub system to send the command
		// 3. Updating the agent's status to indicate a pending scan
		// For now, we'll just return a success response indicating the scan was queued
		response := map[string]interface{}{
			"status":    "success",
			"agent_id":  req.AgentID,
			"scan_type": req.ScanType,
			"message":   "Scan has been queued for execution",
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	}
}