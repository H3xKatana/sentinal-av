package signatures

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/0xA1M/sentinel-server/internal/models"
	"gorm.io/gorm"
)

// Service provides signature management functionality
type Service struct {
	DB *gorm.DB
}

// NewService creates a new signature service
func NewService(db *gorm.DB) *Service {
	return &Service{DB: db}
}

// ValidateYARA validates the syntax of a YARA rule
func (s *Service) ValidateYARA(rule string) error {
	// Basic validation: ensure the rule has proper structure
	// In a real implementation, we would use the YARA library to validate the rule
	if !strings.Contains(rule, "rule ") {
		return fmt.Errorf("invalid YARA rule: missing 'rule' declaration")
	}

	if !strings.Contains(rule, "{") || !strings.Contains(rule, "}") {
		return fmt.Errorf("invalid YARA rule: missing rule body")
	}

	return nil
}

// ValidateHash validates that the hash is a proper MD5 or SHA256 hash
func (s *Service) ValidateHash(hash string) error {
	// Check if it's an MD5 hash (32 hexadecimal characters)
	md5Regex := regexp.MustCompile(`^[a-fA-F0-9]{32}$`)

	// Check if it's a SHA256 hash (64 hexadecimal characters)
	sha256Regex := regexp.MustCompile(`^[a-fA-F0-9]{64}$`)

	if !md5Regex.MatchString(hash) && !sha256Regex.MatchString(hash) {
		return fmt.Errorf("invalid hash: not a valid MD5 or SHA256 hash")
	}

	return nil
}

// ImportYARARulesFromFiles imports YARA rules from files in a given directory
func (s *Service) ImportYARARulesFromFiles(dirPath string) error {
	// Walk through the directory
	err := filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Process only .yar or .yara files
		if !info.IsDir() && (strings.HasSuffix(strings.ToLower(path), ".yar") || strings.HasSuffix(strings.ToLower(path), ".yara")) {
			content, err := os.ReadFile(path)
			if err != nil {
				return err
			}

			ruleContent := string(content)

			// Validate the rule
			if err := s.ValidateYARA(ruleContent); err != nil {
				return fmt.Errorf("invalid rule in file %s: %v", path, err)
			}

			// Extract rule name from content
			ruleName := extractRuleName(ruleContent)

			// Create a signature
			signature := models.Signature{
				Name:        ruleName,
				Type:        "yara",
				Content:     ruleContent,
				Description: fmt.Sprintf("Imported from file: %s", path),
				Status:      "active",
				CreatedBy:   "system",
				CreatedAt:   time.Now(),
				UpdatedAt:   time.Now(),
			}

			// Save to database
			result := s.DB.Create(&signature)
			if result.Error != nil {
				return result.Error
			}
		}

		return nil
	})

	return err
}

// ImportHashesFromFiles imports hash signatures from files
func (s *Service) ImportHashesFromFiles(filePath string, hashType string) error {
	content, err := os.ReadFile(filePath)
	if err != nil {
		return err
	}

	// Split content by lines
	lines := strings.SplitSeq(string(content), "\n")

	for line := range lines {
		// Trim whitespace
		hash := strings.TrimSpace(line)

		// Skip empty lines and comments
		if hash == "" || strings.HasPrefix(hash, "#") {
			continue
		}

		// Validate hash
		if err := s.ValidateHash(hash); err != nil {
			return fmt.Errorf("invalid hash in file %s: %s - %v", filePath, hash, err)
		}

		// Create a signature
		signature := models.Signature{
			Name:        fmt.Sprintf("%s_hash_%s", hashType, hash[:8]), // Use first 8 chars of hash as name
			Type:        "hash",
			Content:     hash,
			HashType:    hashType,
			Description: fmt.Sprintf("%s hash signature", hashType),
			Status:      "active",
			CreatedBy:   "system",
			CreatedAt:   time.Now(),
			UpdatedAt:   time.Now(),
		}

		// Save to database
		result := s.DB.Create(&signature)
		if result.Error != nil {
			return result.Error
		}
	}

	return nil
}

// extractRuleName extracts the rule name from a YARA rule content
func extractRuleName(ruleContent string) string {
	// Look for the rule declaration: "rule RuleName"
	ruleRegex := regexp.MustCompile(`rule\s+([a-zA-Z_][a-zA-Z0-9_]*)`)
	matches := ruleRegex.FindStringSubmatch(ruleContent)

	if len(matches) > 1 {
		return matches[1]
	}

	// If we can't extract the name, return a default
	return "unknown_rule"
}

// GetAllSignatures returns all signatures of a specific type
func (s *Service) GetAllSignatures(signatureType string) ([]models.Signature, error) {
	var signatures []models.Signature

	query := s.DB.Where("status = ?", "active")
	if signatureType != "" {
		query = query.Where("type = ?", signatureType)
	}

	result := query.Find(&signatures)
	return signatures, result.Error
}

// GetSignature returns a specific signature by ID
func (s *Service) GetSignature(id uint) (*models.Signature, error) {
	var signature models.Signature
	result := s.DB.First(&signature, id)
	return &signature, result.Error
}

// CreateSignature creates a new signature
func (s *Service) CreateSignature(name, signatureType, content, hashType, threatType, description, version, createdBy string) (*models.Signature, error) {
	// Validate the signature content based on type
	switch signatureType {
	case "yara":
		if err := s.ValidateYARA(content); err != nil {
			return nil, err
		}
	case "hash":
		if err := s.ValidateHash(content); err != nil {
			return nil, err
		}
	case "heuristic":
		// For heuristic rules, we might want to validate differently
		// For now, just accept the content
	default:
		return nil, fmt.Errorf("unsupported signature type: %s", signatureType)
	}

	signature := models.Signature{
		Name:        name,
		Type:        signatureType,
		Content:     content,
		HashType:    hashType,
		ThreatType:  threatType,
		Description: description,
		Version:     version,
		Status:      "active",
		CreatedBy:   createdBy,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	result := s.DB.Create(&signature)
	if result.Error != nil {
		return nil, result.Error
	}

	return &signature, nil
}

// UpdateSignature updates an existing signature
func (s *Service) UpdateSignature(id uint, updates map[string]any) error {
	// Validate content if it's being updated
	if content, ok := updates["Content"].(string); ok {
		var signatureType string
		var existingSig models.Signature
		result := s.DB.First(&existingSig, id)
		if result.Error != nil {
			return result.Error
		}
		signatureType = existingSig.Type

		// If type is also being updated, use the new type
		if newType, ok := updates["Type"].(string); ok {
			signatureType = newType
		}

		switch signatureType {
		case "yara":
			if err := s.ValidateYARA(content); err != nil {
				return err
			}
		case "hash":
			if err := s.ValidateHash(content); err != nil {
				return err
			}
		}
	}

	updates["UpdatedAt"] = time.Now()
	result := s.DB.Model(&models.Signature{}).Where("id = ?", id).Updates(updates)
	return result.Error
}

// DeleteSignature marks a signature as deleted
func (s *Service) DeleteSignature(id uint) error {
	updates := map[string]any{
		"Status":    "deleted",
		"UpdatedAt": time.Now(),
	}

	result := s.DB.Model(&models.Signature{}).Where("id = ?", id).Updates(updates)
	return result.Error
}

// GetSignaturesByThreatType returns signatures filtered by threat type
func (s *Service) GetSignaturesByThreatType(threatType string) ([]models.Signature, error) {
	var signatures []models.Signature
	result := s.DB.Where("status = ? AND threat_type = ?", "active", threatType).Find(&signatures)
	return signatures, result.Error
}

// GetActiveYARASignatures returns all active YARA signatures
func (s *Service) GetActiveYARASignatures() ([]models.Signature, error) {
	return s.GetAllSignatures("yara")
}

// GetActiveHashSignatures returns all active hash signatures
func (s *Service) GetActiveHashSignatures() ([]models.Signature, error) {
	return s.GetAllSignatures("hash")
}
