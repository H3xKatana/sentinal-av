package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/0xA1M/sentinel-server/grpc"
	"github.com/0xA1M/sentinel-server/internal/api"
	"github.com/0xA1M/sentinel-server/internal/auth"
	"github.com/0xA1M/sentinel-server/internal/db"
	"github.com/0xA1M/sentinel-server/internal/scheduler"
	"github.com/0xA1M/sentinel-server/internal/signatures"
	syncsvc "github.com/0xA1M/sentinel-server/internal/sync"
)

func main() {
	log.Println("Starting Sentinel server initialization...")

	// Initialize database connection
	database, err := db.Connect()
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}

	log.Println("Database connection established successfully")

	// Run database migrations
	if err := db.Migrate(); err != nil {
		log.Fatalf("Failed to migrate database: %v", err)
	}

	log.Println("Database migrations completed successfully")

	// Initialize services
	authSvc := auth.NewService(database)
	signatureSvc := signatures.NewService(database)
	syncSvc := syncsvc.NewService(database, signatureSvc)
	schedulerSvc := scheduler.NewService(database, syncSvc)

	log.Println("Services initialized successfully")

	// Start the scheduler
	schedulerSvc.Start()
	log.Println("Scheduler started successfully")

	// Start gRPC server for agent communication
	grpcServer := grpc.NewServer(database, authSvc)
	grpcPort := getEnv("GRPC_PORT", "50051")

	go func() {
		log.Printf("Starting gRPC server on port %s", grpcPort)
		if err := grpcServer.Start(grpcPort); err != nil {
			log.Fatalf("Failed to start gRPC server: %v", err)
		}
	}()

	// Set up HTTP API server for web UI
	router := api.Router(database, authSvc)

	// Add health check endpoints for container orchestration
	router.PathPrefix("/health").HandlerFunc(healthHandler).Methods("GET")
	router.PathPrefix("/live").HandlerFunc(livenessHandler).Methods("GET")

	httpPort := getEnv("HTTP_PORT", "3000")
	addr := fmt.Sprintf(":%s", httpPort)

	// Create HTTP server with timeouts for production
	httpServer := &http.Server{
		Addr:         addr,
		Handler:      router,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	log.Printf("Starting HTTP API server on port %s", httpPort)

	// Start HTTP server in a goroutine
	go func() {
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Failed to start HTTP server: %v", err)
		}
	}()

	log.Printf("Sentinel server started successfully - HTTP: %s, gRPC: %s", httpPort, grpcPort)

	// Wait for interrupt signal to gracefully shutdown the server
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	log.Println("Shutting down servers gracefully...")

	// Give outstanding requests a deadline for completion
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Shutdown HTTP server
	if err := httpServer.Shutdown(ctx); err != nil {
		log.Printf("HTTP server shutdown error: %v", err)
	}

	// Stop gRPC server
	grpcServer.Stop()

	// Stop scheduler
	schedulerSvc.Stop()

	log.Println("Servers shut down successfully")
}

// getEnv retrieves an environment variable or returns a default value
func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// healthHandler provides a readiness health check
func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, `{"status": "healthy", "service": "sentinel-server", "timestamp": "`+time.Now().Format(time.RFC3339)+`"}`)
}

// livenessHandler provides a liveness health check
func livenessHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, `{"status": "alive", "service": "sentinel-server", "timestamp": "`+time.Now().Format(time.RFC3339)+`"}`)
}
