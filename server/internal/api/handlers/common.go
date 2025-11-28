package handlers

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/0xA1M/sentinel-server/internal/models"
)

// GetDashboardStatsHandler returns dashboard statistics
func GetDashboardStatsHandler(agentSvc *AgentService, scanSvc *ScanService, eventSvc *EventService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Count active agents
		var activeAgentsCount int64
		agentSvc.DB.Model(&models.Agent{}).Where("is_active = ?", true).Count(&activeAgentsCount)

		// Count scan results in the last 24 hours
		var recentScansCount int64
		scanSvc.DB.Model(&models.ScanResult{}).Where("scan_time > ?", time.Now().Add(-24*time.Hour)).Count(&recentScansCount)

		// Count events in the last 24 hours
		var recentEventsCount int64
		eventSvc.DB.Model(&models.Event{}).Where("timestamp > ?", time.Now().Add(-24*time.Hour)).Count(&recentEventsCount)

		// Count threats found in the last 24 hours
		var threatsCount int64
		scanSvc.DB.Table("threats").Where("created_at > ?", time.Now().Add(-24*time.Hour)).Count(&threatsCount)

		// Get system status summary
		var systemStatus models.SystemStatus
		// For now, just get the latest status - in a real implementation, this would calculate based on system health
		agentSvc.DB.Last(&systemStatus)

		stats := map[string]any{
			"agents_online":    activeAgentsCount,
			"last_24h_scans":   recentScansCount,
			"last_24h_events":  recentEventsCount,
			"last_24h_threats": threatsCount,
			"system_health":    "good", // Placeholder - would be calculated based on various metrics
			"last_updated":     time.Now(),
			"active_scans":     0, // Placeholder - would track real-time active scans
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(stats)
	}
}

// HealthHandler is a simple health check endpoint
func HealthHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	resp := map[string]any{
		"status":  "ok",
		"time":    time.Now().Format(time.RFC3339),
		"service": "sentinel-server",
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}
