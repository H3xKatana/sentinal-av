package db

import (
	"fmt"
	"os"

	"github.com/0xA1M/sentinel-server/internal/api/utils"
	"github.com/0xA1M/sentinel-server/internal/db/migrations"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

// DB is the database instance
var DB *gorm.DB

// Connect initializes the database connection
func Connect() (*gorm.DB, error) {
	dsn := fmt.Sprintf("host=%s user=%s password=%s dbname=%s port=%s sslmode=%s TimeZone=%s",
		getEnv("DB_HOST", "localhost"),
		getEnv("DB_USER", "sentinel"),
		getEnv("DB_PASSWORD", "sentinel"),
		getEnv("DB_NAME", "sentinel_av"),
		getEnv("DB_PORT", "5432"),
		getEnv("DB_SSLMODE", "disable"),
		getEnv("DB_TIMEZONE", "UTC"),
	)

	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{
		Logger: utils.GetGormLogger(),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %v", err)
	}

	DB = db
	return db, nil
}

// Migrate runs the database migrations
func Migrate() error {
	return migrations.Migrate(DB)
}

// getEnv retrieves an environment variable or returns a default value
func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
