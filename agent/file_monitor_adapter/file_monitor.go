package file_monitor_adapter

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// FileMonitor checks for suspicious file system activity
type FileMonitor struct {
	config     MonitorConfig
	running    bool
	events     chan SuspiciousEvent
	stopChan   chan struct{}
	fileStates map[string]time.Time // Track file modification times
}

// NewFileMonitor creates a new file monitor with the given configuration
func NewFileMonitor(config MonitorConfig) *FileMonitor {
	if config.ScanInterval == 0 {
		config.ScanInterval = 10 * time.Second // Default to 10 seconds
	}

	if len(config.SuspiciousPaths) == 0 {
		// Default suspicious paths on Linux
		config.SuspiciousPaths = []string{
			"/tmp",
			"/var/tmp",
			"/dev/shm",
			"/run",
			"/home", // Monitor user home directories
		}
	}

	if config.CPULimit == 0 {
		config.CPULimit = 40.0 // Default to 40%
	}

	if config.MemoryLimit == 0 {
		config.MemoryLimit = 40.0 // Default to 40%
	}

	return &FileMonitor{
		config:     config,
		events:     make(chan SuspiciousEvent, 100), // Buffered channel
		stopChan:   make(chan struct{}),
		fileStates: make(map[string]time.Time),
	}
}

// monitorSuspiciousPaths continuously monitors suspicious paths for new/modified files
func (fm *FileMonitor) monitorSuspiciousPaths() {
	ticker := time.NewTicker(fm.config.ScanInterval)
	defer ticker.Stop()

	// Initial scan to establish baseline
	fm.scanSuspiciousPaths()

	for {
		select {
		case <-ticker.C:
			fm.scanSuspiciousPaths()
		case <-fm.stopChan:
			return
		}
	}
}

// scanSuspiciousPaths scans the configured paths for new or modified files
func (fm *FileMonitor) scanSuspiciousPaths() {
	for _, path := range fm.config.SuspiciousPaths {
		// Handle home directory monitoring separately to check all user directories
		if path == "/home" {
			fm.scanHomeDirectories()
			continue
		}

		err := filepath.Walk(path, func(filePath string, info os.FileInfo, err error) error {
			if err != nil {
				// Skip files we don't have permissions to access
				return nil
			}

			// Skip directories
			if info.IsDir() {
				return nil
			}

			// Check if this is a new file or if it has been modified
			modTime := info.ModTime()
			cachedTime, exists := fm.fileStates[filePath]

			// If file didn't exist before or has been modified since last check
			if !exists || modTime.After(cachedTime) {
				// Check if this file could be suspicious based on name or extension
				if fm.isSuspiciousFile(filePath, info) {
					event := SuspiciousEvent{
						ID:          fmt.Sprintf("file_suspicious_%d", time.Now().UnixNano()),
						Timestamp:   time.Now(),
						EventType:   "suspicious_file",
						Description: fmt.Sprintf("Suspicious file detected: %s", filePath),
						Severity:    "high",
						FilePath:    filePath,
						Details: map[string]interface{}{
							"size":       info.Size(),
							"mod_time":   modTime,
							"mode":       info.Mode().String(),
							"is_new":     !exists,
							"extension":  filepath.Ext(filePath),
						},
					}
					select {
					case fm.events <- event:
						// Event sent successfully
					default:
						// Channel is full, skip event to prevent blocking
					}
				}
			}

			// Update the file state
			fm.fileStates[filePath] = modTime

			return nil
		})

		if err != nil {
			// Log the error but continue with other paths
			event := SuspiciousEvent{
				ID:          fmt.Sprintf("error_%d", time.Now().UnixNano()),
				Timestamp:   time.Now(),
				EventType:   "monitor_error",
				Description: fmt.Sprintf("Error scanning path %s: %v", path, err),
				Severity:    "low",
				FilePath:    path,
			}
			select {
			case fm.events <- event:
			default:
				// Channel is full
			}
		}
	}
}

// scanHomeDirectories monitors all user home directories
func (fm *FileMonitor) scanHomeDirectories() {
	homeDir := "/home"
	entries, err := os.ReadDir(homeDir)
	if err != nil {
		return // No home directory or not accessible
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue // Skip files in /home itself
		}

		userHome := filepath.Join(homeDir, entry.Name())

		// Look for suspicious locations in user home directories
		suspiciousUserPaths := []string{
			userHome,
			filepath.Join(userHome, ".ssh"),
			filepath.Join(userHome, ".config"),
			filepath.Join(userHome, "Downloads"),
			filepath.Join(userHome, ".local/bin"),
			filepath.Join(userHome, ".bashrc"),
			filepath.Join(userHome, ".profile"),
			filepath.Join(userHome, ".zshrc"),
		}

		for _, path := range suspiciousUserPaths {
			if _, err := os.Stat(path); os.IsNotExist(err) {
				continue // Path doesn't exist, skip
			}

			// Scan this specific path
			_ = filepath.Walk(path, func(filePath string, info os.FileInfo, err error) error {
				if err != nil {
					// Skip files we don't have permissions to access
					return nil
				}

				// Skip directories
				if info.IsDir() {
					return nil
				}

				// Check if this is a new file or if it has been modified
				modTime := info.ModTime()
				cachedTime, exists := fm.fileStates[filePath]

				// If file didn't exist before or has been modified since last check
				if !exists || modTime.After(cachedTime) {
					// Check if this file could be suspicious based on name or extension
					if fm.isSuspiciousFile(filePath, info) {
						event := SuspiciousEvent{
							ID:          fmt.Sprintf("user_file_suspicious_%d", time.Now().UnixNano()),
							Timestamp:   time.Now(),
							EventType:   "suspicious_user_file",
							Description: fmt.Sprintf("Suspicious file detected in user directory: %s", filePath),
							Severity:    "medium",
							FilePath:    filePath,
							Details: map[string]interface{}{
								"size":       info.Size(),
								"mod_time":   modTime,
								"mode":       info.Mode().String(),
								"is_new":     !exists,
								"extension":  filepath.Ext(filePath),
								"username":   entry.Name(),
							},
						}
						select {
						case fm.events <- event:
							// Event sent successfully
						default:
							// Channel is full, skip event to prevent blocking
						}
					}
				}

				// Update the file state
				fm.fileStates[filePath] = modTime

				return nil
			})
		}
	}
}

// isSuspiciousFile determines if a file is potentially suspicious based on its name, path, extension, etc.
func (fm *FileMonitor) isSuspiciousFile(filePath string, info os.FileInfo) bool {
	// Convert to lowercase for comparison
	lowerPath := strings.ToLower(filePath)

	// Check if filename contains "malware" (our simple detection trigger)
	baseName := strings.ToLower(filepath.Base(filePath))
	if strings.Contains(baseName, "malware") {
		return true
	}

	// Check for suspicious extensions
	suspiciousExts := []string{
		".exe", ".scr", ".bat", ".cmd", ".com", ".pif", ".vbs", ".js", ".jse",
		".vbe", ".wsf", ".wsh", ".msi", ".msp", ".hta", ".cpl", ".dll", ".sys",
		".bin", ".sh", ".deb", ".rpm", // Executable/script extensions on Linux
	}

	ext := strings.ToLower(filepath.Ext(filePath))
	for _, suspiciousExt := range suspiciousExts {
		if ext == suspiciousExt {
			return true
		}
	}

	// Check for suspicious filenames
	suspiciousNames := []string{
		"keygen", "crack", "patch", "trojan", "virus",
		"backdoor", "rootkit", "ransomware", "worm", "spyware",
		"adware", "bot", "miner", "payload", "shellcode", "exploit",
	}

	for _, suspiciousName := range suspiciousNames {
		if strings.Contains(baseName, suspiciousName) {
			return true
		}
	}

	// Check if it's an executable in a suspicious location
	if strings.HasSuffix(lowerPath, "/tmp") ||
	   strings.Contains(lowerPath, "/dev/shm") ||
	   strings.Contains(lowerPath, "/var/tmp") {
		// If it's executable in a temporary location, it's suspicious
		if info.Mode()&0111 != 0 { // Check if any execute bits are set
			return true
		}
	}

	// Check for hidden executable files in home directories
	if strings.Contains(lowerPath, "/home") &&
	   strings.HasPrefix(filepath.Base(filePath), ".") &&
	   info.Mode()&0111 != 0 {
		return true
	}

	// Check for files in common malware locations
	suspiciousPaths := []string{
		".ssh/authorized_keys", // Unexpected changes to SSH keys
		"/etc/passwd",          // Changes to user accounts
		"/etc/shadow",          // Changes to passwords
		"/etc/cron",            // Changes to scheduled tasks
		"/etc/init.d/",         // Changes to startup scripts
		"/etc/rc.d/",           // Changes to startup scripts
		"/usr/local/bin/",      // Unexpected binaries in user bin
		"/usr/bin/",            // Changes to system binaries
		"/bin/",                // Changes to system binaries
	}

	for _, suspiciousPath := range suspiciousPaths {
		if strings.Contains(lowerPath, suspiciousPath) {
			return true
		}
	}

	return false
}

// Start begins file monitoring in the background
func (fm *FileMonitor) Start() error {
	if fm.running {
		return fmt.Errorf("file monitor is already running")
	}

	fm.running = true

	// Start the monitoring loop in a goroutine
	go fm.monitorSuspiciousPaths()

	return nil
}

// Stop halts file monitoring
func (fm *FileMonitor) Stop() error {
	if !fm.running {
		return fmt.Errorf("file monitor is not running")
	}

	close(fm.stopChan)
	fm.running = false

	return nil
}

// IsRunning returns whether the file monitor is active
func (fm *FileMonitor) IsRunning() bool {
	return fm.running
}

// GetEvents returns a channel of detected suspicious events
func (fm *FileMonitor) GetEvents() <-chan SuspiciousEvent {
	return fm.events
}