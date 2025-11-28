package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/joho/godotenv"
	vtadapter "github.com/0xA1M/sentinel-agent/vt_adapter"
	monitoradapter "github.com/0xA1M/sentinel-agent/file_monitor_adapter"
	"github.com/0xA1M/sentinel-agent/common"
	"github.com/0xA1M/sentinel-agent/exporter"
	"github.com/0xA1M/sentinel-agent/scheduler"
)

// Global variable to track the agent's numeric ID after registration and lookup
var agentNumericID uint = 1 // Default to 1 if we can't determine it properly

func main() {
	// Load environment variables from .env file
	err := godotenv.Load()
	if err != nil {
		log.Println("No .env file found, using system environment variables")
	}

	var path string
	var runOnce bool
	var enableMonitoring bool
	// Check environment variable for default scan path
	defaultPath := os.Getenv("AGENT_SCAN_PATH")
	if defaultPath == "" {
		defaultPath = "." // Default to current directory if not set
	}
	flag.StringVar(&path, "path", defaultPath, "File or directory to scan")
	flag.BoolVar(&runOnce, "once", false, "Run scan once and exit (don't start scheduler)")
	flag.BoolVar(&enableMonitoring, "monitor", false, "Enable real-time system monitoring")
	flag.Parse()

	agentName := "agent-47"

	// Get server URL from environment variable
	serverURL := os.Getenv("SERVER_URL")
	if serverURL == "" {
		serverURL = "http://localhost:3000" // Default URL - just the base, not the /data endpoint
	}

	// Create exporter
	exporterConfig := exporter.Config{
		ServerURL:  serverURL + "/api/data", // Use the /api/data endpoint for other data types
		AgentID:    agentName,
		Timeout:    30 * time.Second,
		RetryCount: 3,
		RetryDelay: 5 * time.Second,
	}
	dataExporter := exporter.NewHTTPExporter(exporterConfig)
	if err := dataExporter.Start(); err != nil {
		log.Fatalf("Failed to start exporter: %v", err)
	}
	defer dataExporter.Stop()

	// Create alert client for the new /api/alert endpoint
	alertClient := common.NewAlertClient(serverURL + "/api")

	// Create command client for polling commands from the server
	commandClient := common.NewCommandClient(serverURL+"/api/commands", agentName)

	// Register the agent with the server
	err = registerAgent(serverURL, agentName)
	if err != nil {
		log.Printf("Warning: Failed to register agent: %v", err)
	} else {
		log.Printf("Agent registered successfully: %s", agentName)
		// For a simple local setup, we'll assume the first registered agent gets ID 1
		// In a production implementation, we'd retrieve the actual numeric ID
		agentNumericID = 1 // Set the global agent ID variable for command polling
	}

	// Get VirusTotal API key from environment variable
	vtAPIKey := os.Getenv("VT_KEY")
	if vtAPIKey == "" {
		log.Fatal("VT_KEY environment variable is required")
	}

	// Create VirusTotal adapter
	vtAdapter, err := vtadapter.NewVTAdapter(vtAPIKey)
	if err != nil {
		log.Fatalf("Failed to create VirusTotal adapter: %v", err)
	}
	defer vtAdapter.Close()

	// For monitoring mode, we don't need the scanner but we still need the VT adapter
	var scanner interface{}
	scanner = vtadapter.NewVTScanner(vtAdapter)
	fmt.Println("Using VirusTotal adapter for scanning...")

	// If running once, just perform the scan and exit
	if runOnce {
		fmt.Println("Running single scan...")
		infectedFiles, err := runScan(scanner, path, dataExporter, agentName)
		if err != nil {
			log.Fatalf("Scan failed: %v", err)
		}
		fmt.Printf("Scan complete. Found infected files: %v\n", infectedFiles)
		return
	}

	// Create scheduler
	jobScheduler := scheduler.NewInMemoryScheduler()

	// Schedule regular scan job
	scanJob := func() error {
		log.Printf("Starting scheduled scan job...")
		_, err := runScan(scanner, path, dataExporter, agentName)
		if err != nil {
			log.Printf("Scheduled scan job failed: %v", err)
			return err
		}
		log.Printf("Scheduled scan job completed")
		return nil
	}

	if err := jobScheduler.ScheduleFunc("regular-scan", "@every 1h", scanJob); err != nil {
		log.Fatalf("Failed to schedule scan job: %v", err)
	}

	// Schedule system status report
	statusJob := func() error {
		log.Printf("Starting system status report job...")
		err := reportSystemStatus(dataExporter, agentName)
		if err != nil {
			log.Printf("System status report job failed: %v", err)
			return err
		}
		log.Printf("System status report job completed")
		return nil
	}

	if err := jobScheduler.ScheduleFunc("system-status", "@every 10m", statusJob); err != nil {
		log.Fatalf("Failed to schedule status job: %v", err)
	}

	// Initialize and start system monitoring if enabled
	var linuxMonitor *monitoradapter.LinuxMonitor
	if enableMonitoring {
		monitorConfig := monitoradapter.MonitorConfig{
			ScanInterval: 10 * time.Second, // Check every 10 seconds
			CPULimit:     40.0,             // 40% CPU threshold
			MemoryLimit:  40.0,             // 40% Memory threshold
		}
		linuxMonitor = monitoradapter.NewLinuxMonitor(monitorConfig)

		// Set VT adapter if available for hash checking of suspicious processes
		if vtAdapter != nil {
			linuxMonitor.SetVTAdapter(vtAdapter)
		}

		if err := linuxMonitor.Start(); err != nil {
			log.Printf("Failed to start system monitoring: %v", err)
		} else {
			fmt.Println("System monitoring started...")

			// Start a goroutine to handle monitoring events and send alerts
			go func() {
				for event := range linuxMonitor.GetEvents() {
					log.Printf("Suspicious event detected: %s - %s", event.EventType, event.Description)

					// Create an alert for the event
					alert := common.Alert{
						Source:      "file_monitor",
						AlertType:   event.EventType,
						Description: event.Description,
						Data: map[string]interface{}{
							"file_path":    event.FilePath,
							"process_name": event.ProcessName,
							"process_id":   event.ProcessID,
							"severity":     event.Severity,
							"details":      event.Details,
							"timestamp":    event.Timestamp,
						},
					}

					// Send the alert to the /alert endpoint
					if err := alertClient.SendAlert(alert); err != nil {
						log.Printf("Failed to send alert: %v", err)
						// If sending to /alert fails, export via the normal data exporter as fallback
						ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
						defer cancel()

						exportData := exporter.Data{
							ID:        event.ID,
							Type:      exporter.ThreatReportType,
							Timestamp: event.Timestamp,
							Payload: map[string]interface{}{
								"event_type":  event.EventType,
								"description": event.Description,
								"severity":    event.Severity,
								"file_path":   event.FilePath,
								"process_name": event.ProcessName,
								"process_id":   event.ProcessID,
								"details":     event.Details,
							},
							AgentID: agentName,
						}

						if err := dataExporter.Export(ctx, exportData); err != nil {
							log.Printf("Failed to export monitoring event as fallback: %v", err)
						}
					}
				}
			}()
		}
	}

	// Start the scheduler
	if err := jobScheduler.Start(); err != nil {
		log.Fatalf("Failed to start scheduler: %v", err)
	}

	// Create signal channel for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	// Start command polling in a separate goroutine
	go func() {
		ticker := time.NewTicker(30 * time.Second) // Poll every 30 seconds
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				// Poll for pending commands using the agent's numeric ID
				commands, err := commandClient.GetPendingCommandsByAgentID(agentNumericID)
				if err != nil {
					log.Printf("Failed to fetch commands: %v", err)
					continue
				}

				for _, cmd := range commands {
					log.Printf("Processing command: %s (ID: %d)", cmd.Command, cmd.ID)

					// Execute the command based on its type
					switch cmd.Command {
					case "scan":
						err := executeScanCommand(cmd, scanner, dataExporter, agentName)
						if err != nil {
							log.Printf("Error executing scan command: %v", err)
							// Update command status to failed
							commandErr := commandClient.UpdateCommandStatus(cmd.ID, "failed", err.Error())
							if commandErr != nil {
								log.Printf("Failed to update command status: %v", commandErr)
							}
						} else {
							// Update command status to completed
							commandErr := commandClient.UpdateCommandStatus(cmd.ID, "completed", "")
							if commandErr != nil {
								log.Printf("Failed to update command status: %v", commandErr)
							}
						}
					default:
						log.Printf("Unknown command: %s", cmd.Command)
						// Update command status to failed for unknown commands
						commandErr := commandClient.UpdateCommandStatus(cmd.ID, "failed", "Unknown command")
						if commandErr != nil {
							log.Printf("Failed to update command status: %v", commandErr)
						}
					}
				}
			case <-sigChan: // Stop polling when the agent is shutting down
				return
			}
		}
	}()

	fmt.Println("Sentinel-AV Agent started with scheduler and exporter...")
	fmt.Printf("Scheduler running with %d jobs\n", len(jobScheduler.Jobs()))

	// Wait for interrupt signal to stop the agent
	<-sigChan

	fmt.Println("\nShutting down agent...")

	if enableMonitoring && linuxMonitor != nil && linuxMonitor.IsRunning() {
		linuxMonitor.Stop()
	}

	jobScheduler.Stop()
}

// Define a common scanner interface that both adapters implement
type FileScanner interface {
	ScanPath(path string) ([]string, error)
}

// runScan performs a scan and exports the results
func runScan(scanner interface{}, path string, dataExporter *exporter.HTTPExporter, agentID string) ([]string, error) {
	startTime := time.Now()

	// Log scan start
	log.Printf("Starting scan: Path=%s, AgentID=%s", path, agentID)

	// Type assert to get the scanner interface
	var fileScanner FileScanner

	// Check if it's a VT scanner
	if vtScanner, ok := scanner.(*vtadapter.VTScanner); ok {
		fileScanner = vtScanner
	} else {
		return nil, fmt.Errorf("unknown scanner type: %T", scanner)
	}

	// Scan the specified path
	infectedFiles, err := fileScanner.ScanPath(path)
	if err != nil {
		log.Printf("Scan failed: Path=%s, Error=%v", path, err)
		return nil, fmt.Errorf("scan failed: %v", err)
	}

	// Log scan completion
	log.Printf("Scan completed: Path=%s, InfectedFiles=%d, Duration=%s",
		path, len(infectedFiles), time.Since(startTime))

	// Create scan result
	scanResult := common.ScanResult{
		ID:          fmt.Sprintf("scan_%d", time.Now().UnixNano()),
		AgentID:     agentID,
		Timestamp:   time.Now(),
		ScannedPath: path,
		Infected:    infectedFiles,
		ScanTime:    time.Since(startTime).String(),
	}

	// Export the scan result
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	exportData := exporter.Data{
		ID:        scanResult.ID,
		Type:      exporter.ScanResultType,
		Timestamp: scanResult.Timestamp,
		Payload:   map[string]interface{}{},
		AgentID:   scanResult.AgentID,
	}
	// Convert struct fields to map for payload
	exportData.Payload["scanned_path"] = scanResult.ScannedPath
	exportData.Payload["infected"] = scanResult.Infected
	exportData.Payload["scan_time"] = scanResult.ScanTime

	if err := dataExporter.Export(ctx, exportData); err != nil {
		log.Printf("Failed to export scan result: %v", err)
	}

	return infectedFiles, nil
}

// executeScanCommand executes a scan command received from the server
func executeScanCommand(cmd common.Command, scanner interface{}, dataExporter *exporter.HTTPExporter, agentID string) error {
	var targetPath string

	// If the command has parameters, try to parse the target path
	if cmd.Params != "" {
		var params map[string]interface{}
		if err := json.Unmarshal([]byte(cmd.Params), &params); err != nil {
			// If JSON parsing fails, use the params as the path directly
			targetPath = cmd.Params
		} else {
			// Otherwise, look for a "target_path" field in the parameters
			if path, ok := params["target_path"].(string); ok {
				targetPath = path
			} else {
				// Default to scanning the current directory if no path specified
				targetPath = "."
			}
		}
	} else {
		// Default to scanning the current directory if no parameters
		targetPath = "."
	}

	log.Printf("Executing scan command: ID=%d, Type=%s, Path=%s, AgentID=%s",
		cmd.ID, cmd.Command, targetPath, agentID)

	// Run the scan
	_, err := runScan(scanner, targetPath, dataExporter, agentID)
	if err != nil {
		log.Printf("Scan command execution failed: ID=%d, Error=%v", cmd.ID, err)
		return fmt.Errorf("scan command execution failed: %v", err)
	}

	log.Printf("Scan command completed: ID=%d, Path=%s", cmd.ID, targetPath)
	return nil
}

// registerAgent registers the agent with the server
func registerAgent(serverURL, agentName string) error {
	// Get system information for registration
	hostname, err := os.Hostname()
	if err != nil {
		hostname = "unknown"
	}

	// Create registration payload
	registrationData := map[string]interface{}{
		"agent_id": agentName,
		"name":     agentName,
		"hostname": hostname,
		"platform": getPlatform(),
		"version":  "1.0.0",
	}

	jsonData, err := json.Marshal(registrationData)
	if err != nil {
		return fmt.Errorf("failed to marshal registration data: %v", err)
	}

	resp, err := http.Post(
		serverURL+"/api/register",
		"application/json",
		bytes.NewBuffer(jsonData),
	)
	if err != nil {
		return fmt.Errorf("failed to send registration request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("registration failed with status: %d", resp.StatusCode)
	}

	return nil
}

// getPlatform returns the current platform
func getPlatform() string {
	platform := "unknown"

	// This could be more sophisticated, but for now we'll keep it simple
	goos := os.Getenv("GOOS")
	if goos != "" {
		platform = goos
	} else {
		// Try to determine the platform in a different way
		// This is a simplified approach - in production you might want to use runtime.GOOS
		platform = "linux" // default for the current focus
	}
	return platform
}

// reportSystemStatus reports the current system status
func reportSystemStatus(dataExporter *exporter.HTTPExporter, agentID string) error {
	log.Printf("Generating system status report for agent: %s", agentID)

	// Create system status report
	status := common.SystemStatus{
		ID:        fmt.Sprintf("status_%d", time.Now().UnixNano()),
		AgentID:   agentID,
		Timestamp: time.Now(),
		Status:    "protected", // In a real implementation, this would reflect actual status
		Uptime:    "0s",        // In a real implementation, this would be actual uptime
		CPUUsage:  0.0,         // In a real implementation, this would be actual CPU usage
		MemUsage:  0.0,         // In a real implementation, this would be actual memory usage
		Version:   "1.0.0",
	}

	// Export the system status
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	exportData := exporter.Data{
		ID:        status.ID,
		Type:      exporter.SystemStatusType,
		Timestamp: status.Timestamp,
		Payload: map[string]interface{}{
			"status":   status.Status,
			"uptime":   status.Uptime,
			"cpu_usage": status.CPUUsage,
			"mem_usage": status.MemUsage,
			"version":  status.Version,
		},
		AgentID: status.AgentID,
	}

	if err := dataExporter.Export(ctx, exportData); err != nil {
		log.Printf("Failed to export system status: %v", err)
		return fmt.Errorf("failed to export system status: %v", err)
	}

	log.Printf("System status report exported successfully for agent: %s", agentID)
	return nil
}
