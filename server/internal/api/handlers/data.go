package handlers

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/0xA1M/sentinel-server/internal/models"
	"github.com/0xA1M/sentinel-server/agent/common"
	"gorm.io/gorm"
)

// DataExportHandler handles data export requests from agents
func DataExportHandler(db *gorm.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Parse the incoming data
		var data map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
			log.Printf("Failed to decode data export request: %v", err)
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}

		// Extract common fields
		dataType, ok := data["type"].(string)
		if !ok {
			http.Error(w, "Missing or invalid data type", http.StatusBadRequest)
			return
		}

		agentID, ok := data["agent_id"].(string)
		if !ok {
			agentID = "unknown"
		}

		// Find the agent in the database by ID
		var agent models.Agent
		result := db.Where("agent_id = ?", agentID).First(&agent)
		if result.Error != nil {
			if result.Error == gorm.ErrRecordNotFound {
				// If agent doesn't exist, create a new one
				agent = models.Agent{
					Name:         agentID,
					AgentID:      agentID,
					Platform:     "unknown",
					Version:      "1.0.0",
					RegisteredAt: time.Now(),
					LastSeen:     &[]time.Time{time.Now()}[0],
					IsActive:     true,
				}
				db.Create(&agent)
			} else {
				log.Printf("Database error when looking up agent: %v", result.Error)
				http.Error(w, "Database error", http.StatusInternalServerError)
				return
			}
		} else {
			// Update the agent's last seen time
			agent.LastSeen = &[]time.Time{time.Now()}[0]
			db.Save(&agent)
		}

		// Process the specific data based on its type following the agent's common types
		switch dataType {
		case "scan_result":
			handleScanResult(db, data, agent.ID)
		case "threat_report":
			handleThreatReport(db, data, agent.ID)
		case "system_status":
			handleSystemStatus(db, data, agent.ID)
		case "agent_status":
			handleAgentStatus(db, data, agent.ID)
		case "metric_data":
			handleMetricData(db, data, agent.ID)
		case "alert":
			handleAlert(db, data, agent.ID)
		default:
			log.Printf("Unknown data type received: %s", dataType)
		}

		// Return success response
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{
			"status": "success",
			"agent":  agentID,
			"type":   dataType,
		})
	}
}

// handleScanResult processes scan result data from agents
func handleScanResult(db *gorm.DB, data map[string]interface{}, agentID uint) {
	// Create a scan result record from agent common.ScanResult structure
	scanResult := models.ScanResult{
		AgentID:  agentID,
		ScanType: "scheduled", // Default scan type
	}

	// Extract scan-specific fields following the agent common types
	if id, ok := data["id"]; ok {
		_ = id // Use ID if provided (not currently used)
	}

	if scannedPath, ok := data["scanned_path"]; ok {
		if pathStr, ok := scannedPath.(string); ok {
			scanResult.FilePaths = append(scanResult.FilePaths, pathStr)
		}
	}

	if infected, ok := data["infected"].([]interface{}); ok {
		for _, item := range infected {
			if filePath, ok := item.(string); ok {
				scanResult.FilePaths = append(scanResult.FilePaths, filePath)

				// Create threat record for each infected file
				scanResultID := scanResult.ID
				threat := models.Threat{
					ScanResultID: &scanResultID,
					AgentID:      &agentID,
					FilePath:     filePath,
					ThreatType:   "malware",
					ThreatName:   "Detected by agent",
					Severity:     "high",
					CreatedAt:    time.Now(),
				}
				db.Create(&threat)
			}
		}
	} else if infected, ok := data["infected"].([]string); ok {
		// Handle case where infected is already a string slice
		for _, filePath := range infected {
			scanResult.FilePaths = append(scanResult.FilePaths, filePath)

			// Create threat record for each infected file
			scanResultID := scanResult.ID
			threat := models.Threat{
				ScanResultID: &scanResultID,
				AgentID:      &agentID,
				FilePath:     filePath,
				ThreatType:   "malware",
				ThreatName:   "Detected by agent",
				Severity:     "high",
				CreatedAt:    time.Now(),
			}
			db.Create(&threat)
		}
	}

	// Parse timestamp if available
	if timestampStr, ok := data["timestamp"].(string); ok {
		if timestamp, err := time.Parse(time.RFC3339, timestampStr); err == nil {
			scanResult.ScanTime = timestamp
		}
	} else if timestamp, ok := data["timestamp"].(time.Time); ok {
		scanResult.ScanTime = timestamp
	} else {
		scanResult.ScanTime = time.Now()
	}

	if _, ok := data["scan_time"].(string); ok {
		// In a real implementation, we might parse this duration and store it in the Duration field
	} else {
		// Set a default duration if not provided
		scanResult.Duration = 0
	}

	// Create the scan result in the database
	result := db.Create(&scanResult)
	if result.Error != nil {
		log.Printf("Failed to create scan result: %v", result.Error)
		return
	}
}

// handleThreatReport processes threat report data from agents
func handleThreatReport(db *gorm.DB, data map[string]interface{}, agentID uint) {
	// Create a threat report following the agent common types
	threat := models.Threat{
		AgentID: &agentID,
	}

	// Extract threat-specific fields following the agent common types
	if filePath, ok := data["file_path"].(string); ok {
		threat.FilePath = filePath
	}

	if threatType, ok := data["threat_type"].(string); ok {
		threat.ThreatType = threatType
	} else {
		threat.ThreatType = "behavioral"
	}

	if severity, ok := data["severity"].(string); ok {
		threat.Severity = severity
	} else {
		threat.Severity = "medium"
	}

	if description, ok := data["description"].(string); ok {
		threat.ThreatName = description
	} else {
		threat.ThreatName = "Behavioral Detection"
	}

	if hash, ok := data["hash"].(string); ok {
		// In a full implementation, we might store the hash
		_ = hash
	}

	threat.CreatedAt = time.Now()

	result := db.Create(&threat)
	if result.Error != nil {
		log.Printf("Failed to create threat report: %v", result.Error)
		return
	}
}

// handleSystemStatus processes system status data from agents
func handleSystemStatus(db *gorm.DB, data map[string]interface{}, agentID uint) {
	// Update agent status based on the system status
	var agent models.Agent
	result := db.First(&agent, agentID)
	if result.Error != nil {
		log.Printf("Failed to find agent for status update: %v", result.Error)
		return
	}

	// Update agent fields based on status data
	if status, ok := data["status"].(string); ok {
		agent.IsActive = (status == "protected")
		// Update quarantine status if needed
		if status == "quarantined" {
			agent.Quarantine = true
		}
	}

	if uptime, ok := data["uptime"].(string); ok {
		// In a real implementation, we might store this in agent metadata
		log.Printf("Agent %d uptime: %s", agentID, uptime)
	}

	if cpuUsage, ok := data["cpu_usage"].(float64); ok {
		// In a real implementation, we might store CPU usage in a metrics table
		log.Printf("Agent %d CPU usage: %.2f%%", agentID, cpuUsage)
	}

	if memUsage, ok := data["mem_usage"].(float64); ok {
		log.Printf("Agent %d Memory usage: %.2f%%", agentID, memUsage)
	}

	if version, ok := data["version"].(string); ok {
		agent.Version = version
	}

	// Save the updated agent
	db.Save(&agent)
}

// handleAgentStatus processes agent status data from agents
func handleAgentStatus(db *gorm.DB, data map[string]interface{}, agentID uint) {
	// Update the agent's status based on the agent status data
	var agent models.Agent
	result := db.First(&agent, agentID)
	if result.Error != nil {
		log.Printf("Failed to find agent for status update: %v", result.Error)
		return
	}

	// Update based on agent status fields
	if status, ok := data["status"].(string); ok {
		agent.IsActive = (status == "running")
		// Update quarantine status if needed
		if status == "quarantined" {
			agent.Quarantine = true
		}
	}

	if version, ok := data["version"].(string); ok {
		agent.Version = version
	}

	if lastScan, ok := data["last_scan"].(string); ok {
		if timestamp, err := time.Parse(time.RFC3339, lastScan); err == nil {
			// In a full implementation, we might store this
			_ = timestamp
		}
	}

	// Update last seen time
	agent.LastSeen = &[]time.Time{time.Now()}[0]
	db.Save(&agent)
}

// handleMetricData processes metric data from agents
func handleMetricData(db *gorm.DB, data map[string]interface{}, agentID uint) {
	// For now, we'll just log the metric data
	log.Printf("Received metric data from agent %d: %v", agentID, data)

	// In a full implementation, you would store the metric data
	// This could include CPU usage, memory usage, disk usage, etc.
}

// handleAlert processes alert data from agents
func handleAlert(db *gorm.DB, data map[string]interface{}, agentID uint) {
	// Create an event representing the alert
	event := models.Event{
		AgentID:     agentID,
		EventType:   "alert",
		EventSource: "agent",
		Timestamp:   time.Now(),
	}

	// Extract alert-specific fields
	if alertType, ok := data["alert_type"].(string); ok {
		event.EventType = alertType
	}

	if description, ok := data["description"].(string); ok {
		event.Description = description
	} else {
		event.Description = "No description provided"
	}

	if severity, ok := data["severity"].(string); ok {
		event.Severity = severity
	} else {
		event.Severity = "high" // Default severity for alerts
	}

	// Add additional data if available
	if alertData, ok := data["data"]; ok {
		// Convert data to JSON string for storage
		dataBytes, err := json.Marshal(alertData)
		if err == nil {
			event.Data = string(dataBytes)
		}
	}

	// Create the event in the database
	result := db.Create(&event)
	if result.Error != nil {
		log.Printf("Failed to create alert event: %v", result.Error)
		return
	}
}

// AlertHandler handles alert requests from agents using the common.Alert structure
func AlertHandler(db *gorm.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var alert common.Alert
		if err := json.NewDecoder(r.Body).Decode(&alert); err != nil {
			log.Printf("Failed to decode alert: %v", err)
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}

		// Find the agent in the database by source
		var agent models.Agent
		result := db.Where("name = ? OR agent_id = ?", alert.Source, alert.Source).First(&agent)
		if result.Error != nil {
			if result.Error == gorm.ErrRecordNotFound {
				// If agent doesn't exist, we can still create the event
				log.Printf("Agent not found for alert source: %s", alert.Source)
			} else {
				log.Printf("Database error when looking up agent for alert: %v", result.Error)
				http.Error(w, "Database error", http.StatusInternalServerError)
				return
			}
		}

		// Create an event for this alert
		event := models.Event{
			EventType:   alert.AlertType,
			EventSource: "agent",
			Description: alert.Description,
			Severity:    "high", // Default severity for alerts
			Timestamp:   time.Now(),
		}

		// Set agent ID if agent was found
		if result.Error == nil {
			event.AgentID = agent.ID

			// Update the agent's last seen time
			now := time.Now()
			agent.LastSeen = &now
			db.Save(&agent)
		}

		// Add additional data if available
		if alert.Data != nil {
			// Convert data to JSON string for storage
			dataBytes, err := json.Marshal(alert.Data)
			if err == nil {
				event.Data = string(dataBytes)
			}
		}

		// Create the event in the database
		result = db.Create(&event)
		if result.Error != nil {
			log.Printf("Failed to create alert event: %v", result.Error)
			http.Error(w, "Failed to store alert", http.StatusInternalServerError)
			return
		}

		// Return success response
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":   "success",
			"event_id": fmt.Sprintf("%d", event.ID),
			"type":     alert.AlertType,
			"source":   alert.Source,
		})
	}
}
