package api

import (
	"github.com/0xA1M/sentinel-server/internal/api/handlers"
	utils "github.com/0xA1M/sentinel-server/internal/api/utils"
	"github.com/0xA1M/sentinel-server/internal/auth"
	"github.com/gorilla/mux"
	"golang.org/x/time/rate"
	"gorm.io/gorm"
)

// Router sets up the main API router with all routes
func Router(db *gorm.DB, authSvc *auth.Service) *mux.Router {
	router := mux.NewRouter()

	// Add security and rate limiting middleware
	router.Use(utils.InputValidationMiddleware)

	// Rate limit public routes at 10 requests per minute with burst of 20
	publicRateLimiter := utils.RateLimitMiddleware(rate.Limit(10), 20, 1)
	router.Use(publicRateLimiter)

	// Initialize services
	agentService := handlers.NewAgentService(db)
	scanService := handlers.NewScanService(db)
	signatureService := handlers.NewSignatureService(db)
	eventService := handlers.NewEventService(db)
	quarantineService := handlers.NewQuarantineService(db)
	userService := handlers.NewUserService(db)
	threatService := handlers.NewThreatService(db)

	// Public routes (no authentication required)
	public := router.PathPrefix("/api").Subrouter()
	public.HandleFunc("/health", handlers.HealthHandler).Methods("GET")
	public.HandleFunc("/register", handlers.CreateAgentHandler(agentService)).Methods("POST")
	public.HandleFunc("/login", handlers.LoginHandler(userService, authSvc)).Methods("POST")

	// Agent data export endpoint (public since agents need to connect before authentication)
	public.HandleFunc("/data", handlers.DataExportHandler(db)).Methods("POST")

	// Agent alert endpoint (public since agents need to connect before authentication)
	public.HandleFunc("/alert", handlers.AlertHandler(db)).Methods("POST")

	// Protected routes (authentication required)
	protected := router.PathPrefix("/api").Subrouter()
	protected.Use(authSvc.AuthMiddleware)

	// Add a higher rate limit for authenticated users (20 requests per minute with burst of 40)
	protected.Use(utils.RateLimitMiddleware(rate.Limit(20), 40, 1))

	// Agent-related routes
	protected.HandleFunc("/agents", handlers.GetAgentsHandler(agentService)).Methods("GET")
	protected.HandleFunc("/agents/{id}", handlers.GetAgentHandler(agentService)).Methods("GET")
	protected.HandleFunc("/agents/{id}", handlers.UpdateAgentHandler(agentService)).Methods("PUT")
	protected.HandleFunc("/agents/{id}", handlers.DeleteAgentHandler(agentService)).Methods("DELETE")
	protected.HandleFunc("/agents/{id}/quarantine", handlers.QuarantineAgentHandler(agentService)).Methods("POST")
	protected.HandleFunc("/agents/{id}/unquarantine", handlers.UnquarantineAgentHandler(agentService)).Methods("POST")
	protected.HandleFunc("/agents/{id}/scans", handlers.GetAgentScansHandler(scanService)).Methods("GET")
	protected.HandleFunc("/agents/{id}/threats", handlers.GetAgentThreatsHandler(threatService)).Methods("GET")
	protected.HandleFunc("/agents/{id}/events", handlers.GetAgentEventsHandler(eventService)).Methods("GET")

	// Scan-related routes
	public.HandleFunc("/scans", handlers.GetScanResultsHandler(scanService)).Methods("GET")
	public.HandleFunc("/scans/{id}", handlers.GetScanResultHandler(scanService)).Methods("GET")
	public.HandleFunc("/scans", handlers.CreateScanResultHandler(scanService)).Methods("POST")
	public.HandleFunc("/scans/{id}/threats", handlers.GetScanThreatsHandler(scanService)).Methods("GET")
	public.HandleFunc("/scans/trigger", handlers.TriggerScanHandler(scanService)).Methods("POST")

	// Threat-related routes
	protected.HandleFunc("/threats", handlers.GetThreatsHandler(threatService)).Methods("GET")
	protected.HandleFunc("/threats/{id}", handlers.GetThreatHandler(threatService)).Methods("GET")
	protected.HandleFunc("/threats", handlers.CreateThreatHandler(threatService)).Methods("POST")
	protected.HandleFunc("/threats/{id}", handlers.UpdateThreatHandler(threatService)).Methods("PUT")
	protected.HandleFunc("/threats/{id}", handlers.DeleteThreatHandler(threatService)).Methods("DELETE")
	protected.HandleFunc("/threats/severity/{severity}", handlers.GetThreatsBySeverityHandler(threatService)).Methods("GET")

	// Signature-related routes
	protected.HandleFunc("/signatures", handlers.GetSignaturesHandler(signatureService)).Methods("GET")
	protected.HandleFunc("/signatures", handlers.CreateSignatureHandler(signatureService)).Methods("POST")
	protected.HandleFunc("/signatures/{id}", handlers.GetSignatureHandler(signatureService)).Methods("GET")
	protected.HandleFunc("/signatures/{id}", handlers.UpdateSignatureHandler(signatureService)).Methods("PUT")
	protected.HandleFunc("/signatures/{id}", handlers.DeleteSignatureHandler(signatureService)).Methods("DELETE")
	protected.HandleFunc("/signatures/sync", handlers.SyncSignaturesHandler(signatureService)).Methods("GET")

	// Event-related routes
	protected.HandleFunc("/events", handlers.GetEventsHandler(eventService)).Methods("GET")
	protected.HandleFunc("/events/{id}", handlers.GetEventHandler(eventService)).Methods("GET")
	protected.HandleFunc("/events", handlers.CreateEventHandler(eventService)).Methods("POST")
	protected.HandleFunc("/events/type/{type}", handlers.GetEventsByTypeHandler(eventService)).Methods("GET")

	// Quarantine-related routes
	protected.HandleFunc("/quarantine", handlers.GetQuarantinedFilesHandler(quarantineService)).Methods("GET")
	protected.HandleFunc("/quarantine/{id}", handlers.GetQuarantinedFileHandler(quarantineService)).Methods("GET")
	protected.HandleFunc("/quarantine/{id}/restore", handlers.RestoreQuarantinedFileHandler(quarantineService)).Methods("POST")
	protected.HandleFunc("/quarantine/{id}/delete", handlers.DeleteQuarantinedFileHandler(quarantineService)).Methods("DELETE")
	protected.HandleFunc("/quarantine", handlers.CreateQuarantinedFileHandler(quarantineService)).Methods("POST")

	// User-related routes
	protected.HandleFunc("/users", handlers.GetUsersHandler(userService)).Methods("GET")
	protected.HandleFunc("/users", handlers.CreateUserHandler(userService, authSvc)).Methods("POST")
	protected.HandleFunc("/users/{id}", handlers.GetUserHandler(userService)).Methods("GET")
	protected.HandleFunc("/users/{id}", handlers.UpdateUserHandler(userService)).Methods("PUT")
	protected.HandleFunc("/users/{id}", handlers.DeleteUserHandler(userService)).Methods("DELETE")
	protected.HandleFunc("/users/profile", handlers.GetProfileHandler(userService)).Methods("GET")
	protected.HandleFunc("/users/profile", handlers.UpdateProfileHandler(userService)).Methods("PUT")
	protected.HandleFunc("/users/change-password", handlers.ChangePasswordHandler(userService, authSvc)).Methods("POST")

	// Command-related routes (for agent communication)
	commandService := handlers.NewCommandService(db)
	public.HandleFunc("/commands", handlers.CreateCommandHandler(commandService)).Methods("POST")
	public.HandleFunc("/commands", handlers.GetPendingCommandsHandler(commandService)).Methods("GET")
	public.HandleFunc("/commands/{id}", handlers.UpdateCommandStatusHandler(commandService)).Methods("PUT")

	// Dashboard statistics
	public.HandleFunc("/dashboard/stats", handlers.GetDashboardStatsHandler(agentService, scanService, eventService)).Methods("GET")
	public.HandleFunc("/dashboard/timeline", handlers.GetTimelineHandler(agentService, scanService, threatService)).Methods("GET")
	public.HandleFunc("/dashboard/agents-status", handlers.GetAgentsStatusHandler(agentService)).Methods("GET")

	return router
}

// Common error response
type ErrorResponse struct {
	Error   string `json:"error"`
	Message string `json:"message,omitempty"`
}

// Success response
type SuccessResponse struct {
	Status  string `json:"status"`
	Message string `json:"message,omitempty"`
	Data    any    `json:"data,omitempty"`
}
