package handlers

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/0xA1M/sentinel-server/internal/models"
	"github.com/gorilla/mux"
	"gorm.io/gorm"
)

// EventService handles event-related operations
type EventService struct {
	DB *gorm.DB
}

// NewEventService creates a new event service
func NewEventService(db *gorm.DB) *EventService {
	return &EventService{DB: db}
}

// GetEventsHandler returns all events
func GetEventsHandler(svc *EventService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var events []models.Event
		result := svc.DB.Preload("Agent").Find(&events)
		if result.Error != nil {
			http.Error(w, "Failed to retrieve events", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(events)
	}
}

// GetEventHandler returns a specific event by ID
func GetEventHandler(svc *EventService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		id, err := strconv.Atoi(vars["id"])
		if err != nil {
			http.Error(w, "Invalid event ID", http.StatusBadRequest)
			return
		}

		var event models.Event
		result := svc.DB.Preload("Agent").First(&event, id)
		if result.Error != nil {
			if result.Error == gorm.ErrRecordNotFound {
				http.Error(w, "Event not found", http.StatusNotFound)
				return
			}
			http.Error(w, "Failed to retrieve event", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(event)
	}
}

// CreateEventHandler creates a new event
func CreateEventHandler(svc *EventService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req models.Event

		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}

		// Validate required fields
		if req.EventType == "" {
			http.Error(w, "EventType is required", http.StatusBadRequest)
			return
		}

		// Create event
		event := models.Event{
			AgentID:     req.AgentID,
			EventType:   req.EventType,
			EventSource: req.EventSource,
			Description: req.Description,
			Severity:    req.Severity,
			Data:        req.Data,
			Timestamp:   req.Timestamp,
		}

		// If AgentID is provided, verify agent exists
		if req.AgentID != 0 {
			var agent models.Agent
			result := svc.DB.First(&agent, req.AgentID)
			if result.Error != nil {
				if result.Error == gorm.ErrRecordNotFound {
					http.Error(w, "Agent not found", http.StatusNotFound)
					return
				}
				http.Error(w, "Failed to verify agent", http.StatusInternalServerError)
				return
			}
		}

		result := svc.DB.Create(&event)
		if result.Error != nil {
			http.Error(w, "Failed to create event", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(event)
	}
}

// GetEventsByTypeHandler returns events filtered by type
func GetEventsByTypeHandler(svc *EventService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		eventType := vars["type"]

		var events []models.Event
		result := svc.DB.Where("event_type = ?", eventType).Preload("Agent").Find(&events)
		if result.Error != nil {
			http.Error(w, "Failed to retrieve events by type", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(events)
	}
}

// GetAgentEventsHandler returns events for a specific agent
func GetAgentEventsHandler(svc *EventService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		agentID, err := strconv.Atoi(vars["id"])
		if err != nil {
			http.Error(w, "Invalid agent ID", http.StatusBadRequest)
			return
		}

		var events []models.Event
		result := svc.DB.Where("agent_id = ?", uint(agentID)).Order("timestamp DESC").Find(&events)
		if result.Error != nil {
			http.Error(w, "Failed to retrieve agent events", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(events)
	}
}