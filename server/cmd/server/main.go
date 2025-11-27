package main

import (
	"encoding/json"
	"log"
	"net/http"
	"time"

	"github.com/0xA1M/sentinel-server/db"
)

type HealthResponse struct {
	Status string `json:"status"`
	Time   string `json:"time"`
}

type RegisterRequest struct {
	AgentName string `json:"agent_name"`
}

type RegisterResponse struct {
	AgentID string `json:"agent_id"`
	Token   string `json:"token"`
}

type ScanResultRequest struct {
	AgentName string   `json:"agent_name"`
	Infected  []string `json:"infected"`
}

type AlertRequest struct {
	Source      string `json:"source"`
	AlertType   string `json:"alert_type"`
	Description string `json:"description"`
	Data        string `json:"data"`
}

var scanResults = make([]ScanResultRequest, 0)

func healthHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	resp := HealthResponse{
		Status: "ok",
		Time:   time.Now().Format(time.RFC3339),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func registerHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Bad requests", http.StatusBadRequest)
		return
	}

	resp := RegisterResponse{
		AgentID: "dummy-agent-id",
		Token:   "dummy-token",
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
	log.Printf("Agent registered: %s\n", req.AgentName)
}

func scanResultHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req ScanResultRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	scanResults = append(scanResults, req)
	log.Printf("Received scan result from %s: %v\n", req.AgentName, req.Infected)

	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"ok"}`))
}

func alertHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req AlertRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	// Insert the alert into the database
	statement, err := db.DB.Prepare("INSERT INTO alerts (source, alert_type, description, data) VALUES (?, ?, ?, ?)")
	if err != nil {
		log.Printf("Failed to prepare statement: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	defer statement.Close()

	_, err = statement.Exec(req.Source, req.AlertType, req.Description, req.Data)
	if err != nil {
		log.Printf("Failed to insert alert: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	log.Printf("Alert received: %s - %s\n", req.AlertType, req.Description)

	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"ok"}`))
}

func main() {
	// Initialize database
	db.InitDB()
	defer db.CloseDB()

	mux := http.NewServeMux()
	mux.HandleFunc("/health", healthHandler)
	mux.HandleFunc("/register", registerHandler)
	mux.HandleFunc("/scan-result", scanResultHandler)
	mux.HandleFunc("/alert", alertHandler)

	log.Println("Sentinel-server started on port :3000")
	if err := http.ListenAndServe(":3000", mux); err != nil {
		log.Fatal(err)
	}
}
