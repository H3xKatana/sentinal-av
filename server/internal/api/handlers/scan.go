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
			threatRecord := models.Threat{
				ScanResultID: scanResult.ID,
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