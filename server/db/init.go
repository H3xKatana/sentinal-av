package db

import (
	"database/sql"
	"log"

	_ "github.com/mattn/go-sqlite3"
)

var DB *sql.DB

// InitDB initializes the SQLite database connection and creates necessary tables
func InitDB() {
	var err error
	DB, err = sql.Open("sqlite3", "./sentinel.db")
	if err != nil {
		log.Fatal("Failed to open database:", err)
	}

	// Create alerts table if it doesn't exist
	statement, err := DB.Prepare(`
		CREATE TABLE IF NOT EXISTS alerts (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
			source TEXT NOT NULL,
			alert_type TEXT NOT NULL,
			description TEXT,
			data TEXT
		)
	`)
	if err != nil {
		log.Fatal("Failed to prepare statement:", err)
	}
	statement.Exec()

	log.Println("Database initialized successfully")
}

// CloseDB closes the database connection
func CloseDB() {
	if DB != nil {
		DB.Close()
	}
}