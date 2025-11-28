package migrations

import (
	"fmt"

	"github.com/0xA1M/sentinel-server/internal/models"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

// Migrate runs the initial database migrations
func Migrate(db *gorm.DB) error {
	// Migrate models individually to avoid GORM confusion about relationships
	err := db.AutoMigrate(&models.User{})
	if err != nil {
		return fmt.Errorf("failed to migrate user model: %v", err)
	}

	err = db.AutoMigrate(&models.Signature{})
	if err != nil {
		return fmt.Errorf("failed to migrate signature model: %v", err)
	}

	err = db.AutoMigrate(&models.SystemStatus{})
	if err != nil {
		return fmt.Errorf("failed to migrate system status model: %v", err)
	}

	err = db.AutoMigrate(&models.Agent{})
	if err != nil {
		return fmt.Errorf("failed to migrate agent model: %v", err)
	}

	err = db.AutoMigrate(&models.ScanResult{})
	if err != nil {
		return fmt.Errorf("failed to migrate scan result model: %v", err)
	}

	err = db.AutoMigrate(&models.Event{})
	if err != nil {
		return fmt.Errorf("failed to migrate event model: %v", err)
	}

	err = db.AutoMigrate(&models.Quarantine{})
	if err != nil {
		return fmt.Errorf("failed to migrate quarantine model: %v", err)
	}

	err = db.AutoMigrate(&models.Threat{})
	if err != nil {
		return fmt.Errorf("failed to migrate threat model: %v", err)
	}

	// Create default admin user if not exists
	var userCount int64
	err = db.Model(&models.User{}).Count(&userCount).Error
	if err != nil {
		return err
	}

	if userCount == 0 {
		// Hash the default admin password
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte("admin123"), bcrypt.DefaultCost)
		if err != nil {
			return err
		}

		adminUser := models.User{
			Username: "admin",
			Email:    "admin@sentinel-av.local",
			Password: string(hashedPassword),
			Role:     "admin",
			IsActive: true,
		}
		err = db.Create(&adminUser).Error
		if err != nil {
			return err
		}
	}

	// Create default signatures if not exists
	var sigCount int64
	err = db.Model(&models.Signature{}).Count(&sigCount).Error
	if err != nil {
		return err
	}

	if sigCount == 0 {
		// Add default signatures
		signatures := []models.Signature{
			{
				Name:        "EICAR-Test-Signature",
				Type:        "hash",
				Content:     "44d88612fea8a8f36de82e1278abb02f", // MD5 of EICAR test string
				HashType:    "md5",
				ThreatType:  "trojan",
				Description: "EICAR test string - used to test antivirus systems",
				Status:      "active",
				CreatedBy:   "system",
			},
		}

		for _, sig := range signatures {
			err = db.Create(&sig).Error
			if err != nil {
				return err
			}
		}
	}

	return nil
}