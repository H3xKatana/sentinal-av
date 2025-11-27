package file_monitor_adapter

import (
	"fmt"
	"sync"
	"time"

	vtadapter "github.com/0xA1M/sentinel-agent/vt_adapter"
)

// LinuxMonitor is a unified system monitor that combines file and process monitoring
type LinuxMonitor struct {
	config      MonitorConfig
	running     bool
	events      chan SuspiciousEvent
	stopChan    chan struct{}
	fileMonitor *FileMonitor
	processMonitor *ProcessMonitor
	eventsList  []SuspiciousEvent
	listMutex   sync.RWMutex
}

// NewLinuxMonitor creates a new unified Linux system monitor
func NewLinuxMonitor(config MonitorConfig) *LinuxMonitor {
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

	monitor := &LinuxMonitor{
		config:   config,
		events:   make(chan SuspiciousEvent, 1000), // Larger buffer for combined events
		stopChan: make(chan struct{}),
		eventsList: make([]SuspiciousEvent, 0),
	}

	// Create file monitor
	monitor.fileMonitor = NewFileMonitor(config)

	// Create process monitor
	monitor.processMonitor = NewProcessMonitor(config)

	return monitor
}

// SetVTAdapter sets the VirusTotal adapter for the process monitor
func (lm *LinuxMonitor) SetVTAdapter(adapter *vtadapter.VTAdapter) {
	lm.processMonitor.SetVTAdapter(adapter)
}

// Start begins both file and process monitoring
func (lm *LinuxMonitor) Start() error {
	if lm.running {
		return fmt.Errorf("Linux monitor is already running")
	}

	lm.running = true

	// Start file monitoring
	if err := lm.fileMonitor.Start(); err != nil {
		return fmt.Errorf("failed to start file monitor: %v", err)
	}

	// Start process monitoring
	if err := lm.processMonitor.Start(); err != nil {
		return fmt.Errorf("failed to start process monitor: %v", err)
	}

	// Start the event collector in a goroutine
	go lm.collectEvents()

	// Start the event processor in a goroutine
	go lm.processEvents()

	return nil
}

// collectEvents collects events from both monitors and forwards them
func (lm *LinuxMonitor) collectEvents() {
	for {
		select {
		case event := <-lm.fileMonitor.GetEvents():
			select {
			case lm.events <- event:
				// Add to internal list for history
				lm.listMutex.Lock()
				lm.eventsList = append(lm.eventsList, event)
				// Keep only the last 100 events to prevent memory issues
				if len(lm.eventsList) > 100 {
					lm.eventsList = lm.eventsList[len(lm.eventsList)-100:]
				}
				lm.listMutex.Unlock()
			default:
				// Channel is full, skip event to prevent blocking
			}
		case event := <-lm.processMonitor.GetEvents():
			select {
			case lm.events <- event:
				// Add to internal list for history
				lm.listMutex.Lock()
				lm.eventsList = append(lm.eventsList, event)
				// Keep only the last 100 events to prevent memory issues
				if len(lm.eventsList) > 100 {
					lm.eventsList = lm.eventsList[len(lm.eventsList)-100:]
				}
				lm.listMutex.Unlock()
			default:
				// Channel is full, skip event to prevent blocking
			}
		case <-lm.stopChan:
			return
		}
	}
}

// processEvents handles events from both monitors
func (lm *LinuxMonitor) processEvents() {
	for {
		select {
		case <-lm.events:
			// Log the event or perform any additional processing
			// In a real implementation, you might want to send events
			// to a logging system or alerting mechanism
		case <-lm.stopChan:
			return
		}
	}
}

// Stop halts both file and process monitoring
func (lm *LinuxMonitor) Stop() error {
	if !lm.running {
		return fmt.Errorf("Linux monitor is not running")
	}

	// Stop file monitor
	if err := lm.fileMonitor.Stop(); err != nil {
		return fmt.Errorf("failed to stop file monitor: %v", err)
	}

	// Stop process monitor
	if err := lm.processMonitor.Stop(); err != nil {
		return fmt.Errorf("failed to stop process monitor: %v", err)
	}

	close(lm.stopChan)
	lm.running = false

	return nil
}

// IsRunning returns whether the Linux monitor is active
func (lm *LinuxMonitor) IsRunning() bool {
	return lm.running
}

// GetEvents returns a channel of detected suspicious events
func (lm *LinuxMonitor) GetEvents() <-chan SuspiciousEvent {
	return lm.events
}

// GetLastEvents returns the most recent suspicious events
func (lm *LinuxMonitor) GetLastEvents(count int) []SuspiciousEvent {
	lm.listMutex.RLock()
	defer lm.listMutex.RUnlock()
	
	if count > len(lm.eventsList) {
		count = len(lm.eventsList)
	}
	
	// Return the last 'count' events
	startIndex := len(lm.eventsList) - count
	if startIndex < 0 {
		startIndex = 0
	}
	
	events := make([]SuspiciousEvent, count)
	copy(events, lm.eventsList[startIndex:])
	
	return events
}

// GetConfig returns the current monitor configuration
func (lm *LinuxMonitor) GetConfig() MonitorConfig {
	return lm.config
}

// UpdateConfig updates the monitor configuration
func (lm *LinuxMonitor) UpdateConfig(config MonitorConfig) error {
	if lm.running {
		return fmt.Errorf("cannot update config while monitor is running")
	}
	
	lm.config = config
	return nil
}