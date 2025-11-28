package db

import (
	"fmt"
	"os"

	"github.com/0xA1M/sentinel-server/internal/api/utils"
	"github.com/0xA1M/sentinel-server/internal/db/migrations"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// DB is the database instance
var DB *gorm.DB

// Connect initializes the database connection
func Connect() (*gorm.DB, error) {
	// Use SQLite database file
	dbPath := getEnv("DB_PATH", "./sentinel.db")

	// Configure SQLite with proper options for concurrent access
	dsn := fmt.Sprintf("%s?_busy_timeout=10000&_journal_mode=WAL&_foreign_keys=on", dbPath)

	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{
		Logger: utils.GetGormLogger(),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %v", err)
	}

	// Set connection pool settings for SQLite
	sqlDB, err := db.DB()
	if err != nil {
		return nil, fmt.Errorf("failed to get database instance: %v", err)
	}

	// Configure connection pool
	sqlDB.SetMaxOpenConns(25) // SQLite works better with fewer connections
	sqlDB.SetMaxIdleConns(25)
	sqlDB.SetConnMaxLifetime(0) // SQLite connections can be long-lived

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
