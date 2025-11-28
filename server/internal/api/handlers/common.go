package handlers

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/0xA1M/sentinel-server/internal/models"
)

// GetTimelineHandler returns a timeline of security events
func GetTimelineHandler(agentSvc *AgentService, scanSvc *ScanService, threatSvc *ThreatService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Get the last 30 days of events
		thirtyDaysAgo := time.Now().AddDate(0, 0, -30)

		var scanResults []models.ScanResult
		scanSvc.DB.Where("scan_time > ?", thirtyDaysAgo).Order("scan_time DESC").Limit(50).Find(&scanResults)

		var threats []models.Threat
		threatSvc.DB.Where("created_at > ?", thirtyDaysAgo).Order("created_at DESC").Limit(50).Find(&threats)

		var events []models.Event
		agentSvc.DB.Where("timestamp > ?", thirtyDaysAgo).Order("timestamp DESC").Limit(50).Find(&events)

		// Create timeline entries
		type TimelineEntry struct {
			Type      string      `json:"type"`      // scan_result, threat, event
			Timestamp time.Time   `json:"timestamp"`
			Data      interface{} `json:"data"`
		}

		var timeline []TimelineEntry

		// Add scan results to timeline
		for _, scan := range scanResults {
			timeline = append(timeline, TimelineEntry{
				Type:      "scan_result",
				Timestamp: scan.ScanTime,
				Data:      scan,
			})
		}

		// Add threats to timeline
		for _, threat := range threats {
			timeline = append(timeline, TimelineEntry{
				Type:      "threat",
				Timestamp: threat.CreatedAt,
				Data:      threat,
			})
		}

		// Add events to timeline
		for _, event := range events {
			timeline = append(timeline, TimelineEntry{
				Type:      "event",
				Timestamp: event.Timestamp,
				Data:      event,
			})
		}

		// Sort timeline by timestamp (most recent first)
		// Simple bubble sort for demonstration - in production, use sort.Slice
		for i := 0; i < len(timeline); i++ {
			for j := 0; j < len(timeline)-i-1; j++ {
				if timeline[j].Timestamp.Before(timeline[j+1].Timestamp) {
					timeline[j], timeline[j+1] = timeline[j+1], timeline[j]
				}
			}
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(timeline)
	}
}

// GetDashboardStatsHandler returns dashboard statistics
func GetDashboardStatsHandler(agentSvc *AgentService, scanSvc *ScanService, eventSvc *EventService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Count active agents
		var activeAgentsCount int64
		agentSvc.DB.Model(&models.Agent{}).Where("is_active = ?", true).Count(&activeAgentsCount)

		// Count agents in quarantine
		var quarantineAgentsCount int64
		agentSvc.DB.Model(&models.Agent{}).Where("quarantine = ?", true).Count(&quarantineAgentsCount)

		// Count scan results in the last 24 hours
		var recentScansCount int64
		scanSvc.DB.Model(&models.ScanResult{}).Where("scan_time > ?", time.Now().Add(-24*time.Hour)).Count(&recentScansCount)

		// Count events in the last 24 hours
		var recentEventsCount int64
		eventSvc.DB.Model(&models.Event{}).Where("timestamp > ?", time.Now().Add(-24*time.Hour)).Count(&recentEventsCount)

		// Count threats found in the last 24 hours
		var threatsCount int64
		scanSvc.DB.Table("threats").Where("created_at > ?", time.Now().Add(-24*time.Hour)).Count(&threatsCount)

		// Get recent threats
		var recentThreats []models.Threat
		scanSvc.DB.Preload("Agent").Order("created_at DESC").Limit(5).Find(&recentThreats)

		// Get agent status summary
		var totalCount, onlineCount, offlineCount int64
		agentSvc.DB.Model(&models.Agent{}).Count(&totalCount)
		agentSvc.DB.Model(&models.Agent{}).Where("last_seen > ?", time.Now().Add(-5*time.Minute)).Count(&onlineCount)
		offlineCount = totalCount - onlineCount

		stats := map[string]interface{}{
			"active_agents_count":   activeAgentsCount,
			"quarantine_agents":     quarantineAgentsCount,
			"recent_scans_count":    recentScansCount,
			"recent_events_count":   recentEventsCount,
			"threats_count":         threatsCount,
			"recent_threats":        recentThreats,
			"agents_total":          totalCount,
			"agents_online":         onlineCount,
			"agents_offline":        offlineCount,
			"system_health":         "good", // Placeholder - would be calculated based on various metrics
			"last_updated":          time.Now(),
			"active_scans":          0, // Placeholder - would track real-time active scans
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

	resp := map[string]interface{}{
		"status":  "ok",
		"time":    time.Now().Format(time.RFC3339),
		"service": "sentinel-server",
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}