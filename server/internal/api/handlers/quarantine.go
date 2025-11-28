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

// QuarantineService handles quarantine-related operations
type QuarantineService struct {
	DB *gorm.DB
}

// NewQuarantineService creates a new quarantine service
func NewQuarantineService(db *gorm.DB) *QuarantineService {
	return &QuarantineService{DB: db}
}

// GetQuarantinedFilesHandler returns all quarantined files
func GetQuarantinedFilesHandler(svc *QuarantineService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var quarantinedFiles []models.Quarantine
		result := svc.DB.Preload("Agent").Find(&quarantinedFiles)
		if result.Error != nil {
			http.Error(w, "Failed to retrieve quarantined files", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(quarantinedFiles)
	}
}

// GetQuarantinedFileHandler returns a specific quarantined file by ID
func GetQuarantinedFileHandler(svc *QuarantineService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		id, err := strconv.Atoi(vars["id"])
		if err != nil {
			http.Error(w, "Invalid quarantined file ID", http.StatusBadRequest)
			return
		}

		var quarantine models.Quarantine
		result := svc.DB.Preload("Agent").First(&quarantine, id)
		if result.Error != nil {
			if result.Error == gorm.ErrRecordNotFound {
				http.Error(w, "Quarantined file not found", http.StatusNotFound)
				return
			}
			http.Error(w, "Failed to retrieve quarantined file", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(quarantine)
	}
}

// RestoreQuarantinedFileHandler restores a quarantined file
func RestoreQuarantinedFileHandler(svc *QuarantineService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		id, err := strconv.Atoi(vars["id"])
		if err != nil {
			http.Error(w, "Invalid quarantined file ID", http.StatusBadRequest)
			return
		}

		var quarantine models.Quarantine
		result := svc.DB.First(&quarantine, id)
		if result.Error != nil {
			if result.Error == gorm.ErrRecordNotFound {
				http.Error(w, "Quarantined file not found", http.StatusNotFound)
				return
			}
			http.Error(w, "Failed to retrieve quarantined file", http.StatusInternalServerError)
			return
		}

		// Update status to restored
		quarantine.Status = "restored"
		quarantine.UpdatedAt = time.Now()

		result = svc.DB.Save(&quarantine)
		if result.Error != nil {
			http.Error(w, "Failed to restore quarantined file", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(quarantine)
	}
}

// DeleteQuarantinedFileHandler permanently deletes a quarantined file
func DeleteQuarantinedFileHandler(svc *QuarantineService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		id, err := strconv.Atoi(vars["id"])
		if err != nil {
			http.Error(w, "Invalid quarantined file ID", http.StatusBadRequest)
			return
		}

		var quarantine models.Quarantine
		result := svc.DB.First(&quarantine, id)
		if result.Error != nil {
			if result.Error == gorm.ErrRecordNotFound {
				http.Error(w, "Quarantined file not found", http.StatusNotFound)
				return
			}
			http.Error(w, "Failed to retrieve quarantined file", http.StatusInternalServerError)
			return
		}

		// Update status to deleted
		quarantine.Status = "deleted"
		quarantine.UpdatedAt = time.Now()

		result = svc.DB.Save(&quarantine)
		if result.Error != nil {
			http.Error(w, "Failed to delete quarantined file", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "success"})
	}
}