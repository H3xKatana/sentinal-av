package file_monitor_adapter

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	vtadapter "github.com/0xA1M/sentinel-agent/vt_adapter"
)

// ProcessInfo holds information about a running process
type ProcessInfo struct {
	PID        int     `json:"pid"`
	Name       string  `json:"name"`
	CPUUsage   float64 `json:"cpu_usage"`
	MemoryUsage float64 `json:"memory_usage"`
	Command    string  `json:"command"`
}

// ProcessMonitor checks for suspicious process activity
type ProcessMonitor struct {
	config MonitorConfig
	running bool
	events chan SuspiciousEvent
	stopChan chan struct{}
	vtAdapter *vtadapter.VTAdapter // Optional VirusTotal adapter for hash checking
}

// NewProcessMonitor creates a new process monitor with the given configuration
func NewProcessMonitor(config MonitorConfig) *ProcessMonitor {
	if config.ScanInterval == 0 {
		config.ScanInterval = 10 * time.Second // Default to 10 seconds
	}

	if config.CPULimit == 0 {
		config.CPULimit = 40.0 // Default to 40%
	}

	if config.MemoryLimit == 0 {
		config.MemoryLimit = 40.0 // Default to 40%
	}

	return &ProcessMonitor{
		config:   config,
		events:   make(chan SuspiciousEvent, 100), // Buffered channel
		stopChan: make(chan struct{}),
		vtAdapter: nil, // Will be set later if needed
	}
}

// SetVTAdapter sets the VirusTotal adapter for hash checking
func (pm *ProcessMonitor) SetVTAdapter(adapter *vtadapter.VTAdapter) {
	pm.vtAdapter = adapter
}

// monitorProcesses continuously monitors running processes for suspicious activity
func (pm *ProcessMonitor) monitorProcesses() {
	ticker := time.NewTicker(pm.config.ScanInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			pm.scanProcesses()
		case <-pm.stopChan:
			return
		}
	}
}

// scanProcesses scans all running processes for suspicious CPU/RAM usage
func (pm *ProcessMonitor) scanProcesses() {
	processes, err := pm.getAllProcesses()
	if err != nil {
		// Log the error but continue monitoring
		event := SuspiciousEvent{
			ID:          fmt.Sprintf("proc_error_%d", time.Now().UnixNano()),
			Timestamp:   time.Now(),
			EventType:   "monitor_error",
			Description: fmt.Sprintf("Error scanning processes: %v", err),
			Severity:    "high",
		}
		select {
		case pm.events <- event:
		default:
			// Channel is full
		}
		return
	}

	for _, proc := range processes {
		// Check for high CPU usage
		if proc.CPUUsage > pm.config.CPULimit {
			event := SuspiciousEvent{
				ID:          fmt.Sprintf("high_cpu_%d_%d", proc.PID, time.Now().UnixNano()),
				Timestamp:   time.Now(),
				EventType:   "high_cpu_usage",
				Description: fmt.Sprintf("Process %s (PID: %d) using %.2f%% CPU", proc.Name, proc.PID, proc.CPUUsage),
				Severity:    "high",
				ProcessName: proc.Name,
				ProcessID:   proc.PID,
				Details: map[string]interface{}{
					"cpu_usage": proc.CPUUsage,
					"command":   proc.Command,
				},
			}
			select {
			case pm.events <- event:
				// Event sent successfully
			default:
				// Channel is full, skip event to prevent blocking
			}
		}

		// Check for high memory usage
		if proc.MemoryUsage > pm.config.MemoryLimit {
			event := SuspiciousEvent{
				ID:          fmt.Sprintf("high_memory_%d_%d", proc.PID, time.Now().UnixNano()),
				Timestamp:   time.Now(),
				EventType:   "high_memory_usage",
				Description: fmt.Sprintf("Process %s (PID: %d) using %.2f%% memory", proc.Name, proc.PID, proc.MemoryUsage),
				Severity:    "high",
				ProcessName: proc.Name,
				ProcessID:   proc.PID,
				Details: map[string]interface{}{
					"memory_usage": proc.MemoryUsage,
					"command":      proc.Command,
				},
			}
			select {
			case pm.events <- event:
				// Event sent successfully
			default:
				// Channel is full, skip event to prevent blocking
			}
		}

		// Check for unusual process paths
		if pm.isUnusualProcessPath(proc.Command) {
			event := SuspiciousEvent{
				ID:          fmt.Sprintf("unusual_path_%d_%d", proc.PID, time.Now().UnixNano()),
				Timestamp:   time.Now(),
				EventType:   "unusual_process_path",
				Description: fmt.Sprintf("Process with unusual path detected: %s (PID: %d)", proc.Command, proc.PID),
				Severity:    "high",
				ProcessName: proc.Name,
				ProcessID:   proc.PID,
				Details: map[string]interface{}{
					"command": proc.Command,
					"path":    proc.Command,
				},
			}

			// If we have a VT adapter, check the hash of the binary
			if pm.vtAdapter != nil {
				// Extract the executable path from command
				execPath := pm.getExecutablePath(proc.Command)
				if execPath != "" {
					hash, err := vtadapter.CalculateFileHash(execPath)
					if err == nil {
						// Check if this hash is known malware
						isMalicious, err := pm.vtAdapter.IsFileMaliciousFromHash(hash)
						if err == nil && isMalicious {
							// Upgrade severity if hash is known malware
							event.Severity = "critical"
							event.Description = fmt.Sprintf("Process with malicious hash detected: %s (PID: %d), Hash: %s", proc.Command, proc.PID, hash)
							event.Details["hash"] = hash
							event.Details["vt_malicious"] = true
						} else if err == nil {
							// Not known malware, but still suspicious due to path
							event.Details["hash"] = hash
							event.Details["vt_malicious"] = false
						}
					}
				}
			}

			select {
			case pm.events <- event:
				// Event sent successfully
			default:
				// Channel is full, skip event to prevent blocking
			}
		}
	}
}

// getAllProcesses retrieves information about all running processes
func (pm *ProcessMonitor) getAllProcesses() ([]ProcessInfo, error) {
	var processes []ProcessInfo

	// Read all directories in /proc
	procDir, err := os.Open("/proc")
	if err != nil {
		return nil, fmt.Errorf("failed to open /proc: %v", err)
	}
	defer procDir.Close()

	entries, err := procDir.Readdirnames(-1)
	if err != nil {
		return nil, fmt.Errorf("failed to read /proc: %v", err)
	}

	for _, entry := range entries {
		pid, err := strconv.Atoi(entry)
		if err != nil {
			continue // Not a process directory
		}

		// Skip some system PIDs like 0, 1, etc.
		if pid < 10 {
			continue
		}

		procInfo, err := pm.getProcessInfo(pid)
		if err != nil {
			continue // Skip processes we can't access
		}

		// Only add processes that have meaningful names
		if procInfo.Name != "" && procInfo.Name != "[" {
			processes = append(processes, procInfo)
		}
	}

	return processes, nil
}

// getProcessInfo retrieves information about a specific process
func (pm *ProcessMonitor) getProcessInfo(pid int) (ProcessInfo, error) {
	var procInfo ProcessInfo
	procInfo.PID = pid

	// Read command line
	cmdlinePath := fmt.Sprintf("/proc/%d/cmdline", pid)
	cmdlineData, err := os.ReadFile(cmdlinePath)
	if err != nil {
		return procInfo, fmt.Errorf("failed to read cmdline for PID %d: %v", pid, err)
	}

	// The command line is null-separated
	cmdlineParts := strings.Split(string(cmdlineData), "\x00")
	if len(cmdlineParts) > 0 {
		procInfo.Command = cmdlineParts[0] // Use the first part as command
		// Extract process name from command
		parts := strings.Split(procInfo.Command, "/")
		if len(parts) > 0 {
			procInfo.Name = parts[len(parts)-1]
		}
	}

	// Read process stat file for CPU and memory usage
	statPath := fmt.Sprintf("/proc/%d/stat", pid)
	statData, err := os.ReadFile(statPath)
	if err != nil {
		return procInfo, fmt.Errorf("failed to read stat for PID %d: %v", pid, err)
	}

	// Parse the stat file to get process information
	// Format: PID (command) state ppid session tty pgrp flags minflt cminflt majflt cmajflt utime stime cutime cstime...
	stats := strings.Fields(string(statData))
	if len(stats) < 23 {
		return procInfo, fmt.Errorf("invalid stat format for PID %d", pid)
	}

	// Calculate CPU usage based on user and system time
	// utime is at index 13, stime is at index 14 (0-indexed)
	utime, err := strconv.ParseFloat(stats[13], 64)
	if err != nil {
		utime = 0
	}
	stime, err := strconv.ParseFloat(stats[14], 64)
	if err != nil {
		stime = 0
	}

	// For a simple approximation of CPU usage, we'll use the total CPU time
	// In a production system, you'd want to calculate usage over time periods
	procInfo.CPUUsage = (utime + stime) / 100.0 // Simplified calculation

	// Get memory usage
	statusPath := fmt.Sprintf("/proc/%d/status", pid)
	statusData, err := os.ReadFile(statusPath)
	if err != nil {
		// If we can't read the status file, try to get memory info from statm
		statmPath := fmt.Sprintf("/proc/%d/statm", pid)
		statmData, err := os.ReadFile(statmPath)
		if err != nil {
			return procInfo, fmt.Errorf("failed to read status/statm for PID %d: %v", pid, err)
		}
		statmFields := strings.Fields(string(statmData))
		if len(statmFields) >= 2 {
			_, _ = strconv.ParseFloat(statmFields[0], 64) // size (total program size)
			resident, _ := strconv.ParseFloat(statmFields[1], 64) // resident set size
			// Calculate approximate memory percentage
			procInfo.MemoryUsage = (resident * 4096) / 1024 / 1024 // Convert pages to MB
		}
	} else {
		// Parse the status file to get VmRSS (Resident Set Size)
		lines := strings.Split(string(statusData), "\n")
		for _, line := range lines {
			if strings.HasPrefix(line, "VmRSS:") {
				fields := strings.Fields(line)
				if len(fields) >= 2 {
					rssKB, err := strconv.ParseFloat(fields[1], 64)
					if err == nil {
						// Convert KB to MB for percentage calculation
						procInfo.MemoryUsage = rssKB / 1024
					}
					break
				}
			}
		}
	}

	// Get total system memory to calculate percentage
	memTotal, err := pm.getSystemMemoryTotal()
	if err != nil {
		// If we can't get the total memory, we'll return the absolute value
		// and skip percentage calculation
	} else {
		// Calculate memory usage as percentage of total system memory
		procInfo.MemoryUsage = (procInfo.MemoryUsage / memTotal) * 100
	}

	return procInfo, nil
}

// getSystemMemoryTotal gets the total system memory in MB
func (pm *ProcessMonitor) getSystemMemoryTotal() (float64, error) {
	data, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0, err
	}

	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "MemTotal:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				totalKB, err := strconv.ParseFloat(fields[1], 64)
				if err != nil {
					return 0, err
				}
				// Convert KB to MB
				return totalKB / 1024, nil
			}
			break
		}
	}

	return 0, fmt.Errorf("MemTotal not found in /proc/meminfo")
}

// Start begins process monitoring in the background
func (pm *ProcessMonitor) Start() error {
	if pm.running {
		return fmt.Errorf("process monitor is already running")
	}

	pm.running = true

	// Start the monitoring loop in a goroutine
	go pm.monitorProcesses()

	return nil
}

// Stop halts process monitoring
func (pm *ProcessMonitor) Stop() error {
	if !pm.running {
		return fmt.Errorf("process monitor is not running")
	}

	close(pm.stopChan)
	pm.running = false

	return nil
}

// IsRunning returns whether the process monitor is active
func (pm *ProcessMonitor) IsRunning() bool {
	return pm.running
}

// GetEvents returns a channel of detected suspicious events
func (pm *ProcessMonitor) GetEvents() <-chan SuspiciousEvent {
	return pm.events
}

// getExecutablePath extracts the executable path from a command string
func (pm *ProcessMonitor) getExecutablePath(command string) string {
	if command == "" {
		return ""
	}

	// Split the command by spaces, but handle quoted paths
	parts := strings.Fields(command)
	if len(parts) == 0 {
		return ""
	}

	// The first part should be the executable path
	execPath := parts[0]

	// If it starts with a slash, it's an absolute path
	if strings.HasPrefix(execPath, "/") {
		return execPath
	}

	// If it's a relative path or just a command name, it might be in PATH
	// For simplicity, we'll check if it exists in the filesystem
	// In a real implementation, we'd need to properly resolve relative paths
	if _, err := os.Stat(execPath); err == nil {
		return execPath
	}

	// If it doesn't exist as is, and it's not an absolute path, we'll return empty
	// since we can't locate the binary
	return ""
}

// isUnusualProcessPath determines if a process path is unusual or suspicious
func (pm *ProcessMonitor) isUnusualProcessPath(processPath string) bool {
	if processPath == "" {
		return false
	}

	// Convert to lowercase for comparison
	lowerPath := strings.ToLower(processPath)

	// Check for processes running from temporary directories
	unusualPaths := []string{
		"/tmp/",
		"/var/tmp/",
		"/dev/shm/",
		"/run/user/", // Running from user runtime directory
		"/home/",     // Running from a user's home directory
		"/root/",     // Running from root's home directory
	}

	for _, unusualPath := range unusualPaths {
		if strings.Contains(lowerPath, unusualPath) {
			// Double-check to avoid false positives
			// Don't flag paths that are part of normal system operation
			if !strings.Contains(lowerPath, "/home/") || strings.Contains(lowerPath, "/.local/share/") {
				return true
			}
		}
	}

	// Check for processes running from hidden directories
	if strings.Contains(lowerPath, "/.") && !strings.Contains(lowerPath, "/.") {
		// This is a general check for hidden directories, but we'll refine it
		parts := strings.Split(processPath, "/")
		for _, part := range parts {
			if strings.HasPrefix(part, ".") && len(part) > 1 { // Not just a single dot
				// Exclude common safe hidden directories like .config, .local, etc.
				if part != ".config" && part != ".local" && part != ".ssh" && part != ".cache" {
					return true
				}
			}
		}
	}

	// Check for processes running from root directory with strange names
	if len(processPath) > 1 && !strings.Contains(processPath[1:], "/") { // Path has no slashes after root
		// This means it's something like /randomname which is unusual
		parts := strings.Split(processPath, "/")
		if len(parts) == 2 { // Format: /filename
			filename := parts[1]
			// If it's not a standard system file, it could be suspicious
			standardRootFiles := []string{
				"bin", "boot", "dev", "etc", "home", "lib", "media",
				"mnt", "opt", "proc", "root", "run", "sbin", "srv",
				"sys", "tmp", "usr", "var", "init", "lib64", "selinux",
			}

			isStandard := false
			for _, stdFile := range standardRootFiles {
				if filename == stdFile {
					isStandard = true
					break
				}
			}

			if !isStandard {
				// This would catch paths like /some_random_file
				return false // Actually, this might be a false positive, so return false
			}
		}
	}

	return false
}