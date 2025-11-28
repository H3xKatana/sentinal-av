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

// SignatureService handles signature-related operations
type SignatureService struct {
	DB *gorm.DB
}

// NewSignatureService creates a new signature service
func NewSignatureService(db *gorm.DB) *SignatureService {
	return &SignatureService{DB: db}
}

// GetSignaturesHandler returns all signatures
func GetSignaturesHandler(svc *SignatureService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var signatures []models.Signature
		result := svc.DB.Where("status != ?", "deleted").Find(&signatures)
		if result.Error != nil {
			http.Error(w, "Failed to retrieve signatures", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(signatures)
	}
}

// GetSignatureHandler returns a specific signature by ID
func GetSignatureHandler(svc *SignatureService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		id, err := strconv.Atoi(vars["id"])
		if err != nil {
			http.Error(w, "Invalid signature ID", http.StatusBadRequest)
			return
		}

		var signature models.Signature
		result := svc.DB.First(&signature, id)
		if result.Error != nil {
			if result.Error == gorm.ErrRecordNotFound {
				http.Error(w, "Signature not found", http.StatusNotFound)
				return
			}
			http.Error(w, "Failed to retrieve signature", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(signature)
	}
}

// CreateSignatureHandler creates a new signature
func CreateSignatureHandler(svc *SignatureService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req models.Signature

		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}

		// Validate required fields
		if req.Name == "" || req.Type == "" || req.Content == "" {
			http.Error(w, "Name, type, and content are required", http.StatusBadRequest)
			return
		}

		// Set default values
		if req.Status == "" {
			req.Status = "active"
		}
		if req.CreatedBy == "" {
			req.CreatedBy = "system" // This should come from the authenticated user in a real implementation
		}

		// Create signature
		signature := models.Signature{
			Name:        req.Name,
			Type:        req.Type,
			Content:     req.Content,
			HashType:    req.HashType,
			ThreatType:  req.ThreatType,
			Description: req.Description,
			Version:     req.Version,
			Status:      req.Status,
			CreatedBy:   req.CreatedBy,
			CreatedAt:   time.Now(),
			UpdatedAt:   time.Now(),
		}

		result := svc.DB.Create(&signature)
		if result.Error != nil {
			http.Error(w, "Failed to create signature", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(signature)
	}
}

// UpdateSignatureHandler updates an existing signature
func UpdateSignatureHandler(svc *SignatureService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		id, err := strconv.Atoi(vars["id"])
		if err != nil {
			http.Error(w, "Invalid signature ID", http.StatusBadRequest)
			return
		}

		var req struct {
			Name        string `json:"name"`
			Content     string `json:"content"`
			HashType    string `json:"hash_type"`
			ThreatType  string `json:"threat_type"`
			Description string `json:"description"`
			Version     string `json:"version"`
			Status      string `json:"status"`
		}

		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}

		var signature models.Signature
		result := svc.DB.First(&signature, id)
		if result.Error != nil {
			if result.Error == gorm.ErrRecordNotFound {
				http.Error(w, "Signature not found", http.StatusNotFound)
				return
			}
			http.Error(w, "Failed to retrieve signature", http.StatusInternalServerError)
			return
		}

		// Update signature fields
		signature.Name = req.Name
		signature.Content = req.Content
		signature.HashType = req.HashType
		signature.ThreatType = req.ThreatType
		signature.Description = req.Description
		signature.Version = req.Version
		signature.Status = req.Status
		signature.UpdatedAt = time.Now()

		result = svc.DB.Save(&signature)
		if result.Error != nil {
			http.Error(w, "Failed to update signature", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(signature)
	}
}

// DeleteSignatureHandler deletes a signature
func DeleteSignatureHandler(svc *SignatureService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		id, err := strconv.Atoi(vars["id"])
		if err != nil {
			http.Error(w, "Invalid signature ID", http.StatusBadRequest)
			return
		}

		var signature models.Signature
		result := svc.DB.First(&signature, id)
		if result.Error != nil {
			if result.Error == gorm.ErrRecordNotFound {
				http.Error(w, "Signature not found", http.StatusNotFound)
				return
			}
			http.Error(w, "Failed to retrieve signature", http.StatusInternalServerError)
			return
		}

		// Soft delete by setting status to deleted
		signature.Status = "deleted"
		signature.UpdatedAt = time.Now()
		result = svc.DB.Save(&signature)
		if result.Error != nil {
			http.Error(w, "Failed to delete signature", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "success"})
	}
}

// SyncSignaturesHandler returns all active signatures for agent synchronization
func SyncSignaturesHandler(svc *SignatureService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var signatures []models.Signature
		result := svc.DB.Where("status = ?", "active").Find(&signatures)
		if result.Error != nil {
			http.Error(w, "Failed to retrieve signatures", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(signatures)
	}
}