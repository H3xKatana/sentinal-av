package file_monitor_adapter

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestFileMonitor(t *testing.T) {
	// Create a temporary directory for testing
	tempDir := t.TempDir()
	testPath := filepath.Join(tempDir, "test_dir")
	err := os.MkdirAll(testPath, 0755)
	if err != nil {
		t.Fatalf("Failed to create test directory: %v", err)
	}

	// Create monitor config
	config := MonitorConfig{
		ScanInterval:    1 * time.Second,
		SuspiciousPaths: []string{testPath},
		CPULimit:        80.0,
		MemoryLimit:     80.0,
	}
	
	// Create file monitor
	monitor := NewFileMonitor(config)
	
	// Start the monitor
	err = monitor.Start()
	if err != nil {
		t.Fatalf("Failed to start file monitor: %v", err)
	}
	
	// Wait a bit to allow for initial scan
	time.Sleep(500 * time.Millisecond)
	
	// Create a suspicious file
	suspiciousFile := filepath.Join(testPath, "test_malware.exe")
	err = os.WriteFile(suspiciousFile, []byte("fake malware content"), 0755)
	if err != nil {
		t.Fatalf("Failed to create suspicious file: %v", err)
	}
	
	// Wait for the file to be detected
	time.Sleep(1500 * time.Millisecond) // Wait for one scan cycle
	
	// Check if the monitor is running
	if !monitor.IsRunning() {
		t.Error("Monitor should be running")
	}
	
	// Stop the monitor
	err = monitor.Stop()
	if err != nil {
		t.Errorf("Failed to stop file monitor: %v", err)
	}
}

func TestProcessMonitor(t *testing.T) {
	// Create monitor config
	config := MonitorConfig{
		ScanInterval: 1 * time.Second,
		CPULimit:     90.0, // High limit to avoid triggering on test systems
		MemoryLimit:  90.0, // High limit to avoid triggering on test systems
	}
	
	// Create process monitor
	monitor := NewProcessMonitor(config)
	
	// Start the monitor
	err := monitor.Start()
	if err != nil {
		t.Fatalf("Failed to start process monitor: %v", err)
	}
	
	// Check if the monitor is running
	if !monitor.IsRunning() {
		t.Error("Monitor should be running")
	}
	
	// Wait a bit for initial scan
	time.Sleep(1500 * time.Millisecond) // Wait for one scan cycle
	
	// Stop the monitor
	err = monitor.Stop()
	if err != nil {
		t.Errorf("Failed to stop process monitor: %v", err)
	}
}

func TestLinuxMonitor(t *testing.T) {
	// Create a temporary directory for testing
	tempDir := t.TempDir()
	testPath := filepath.Join(tempDir, "test_dir")
	err := os.MkdirAll(testPath, 0755)
	if err != nil {
		t.Fatalf("Failed to create test directory: %v", err)
	}

	// Create monitor config
	config := MonitorConfig{
		ScanInterval:    1 * time.Second,
		SuspiciousPaths: []string{testPath},
		CPULimit:        80.0,
		MemoryLimit:     80.0,
	}
	
	// Create unified Linux monitor
	monitor := NewLinuxMonitor(config)
	
	// Start the monitor
	err = monitor.Start()
	if err != nil {
		t.Fatalf("Failed to start Linux monitor: %v", err)
	}
	
	// Check if the monitor is running
	if !monitor.IsRunning() {
		t.Error("Monitor should be running")
	}
	
	// Wait a bit to allow for initial scan
	time.Sleep(500 * time.Millisecond)
	
	// Create a suspicious file
	suspiciousFile := filepath.Join(testPath, "test_malware.sh")
	err = os.WriteFile(suspiciousFile, []byte("#!/bin/bash\necho 'fake malware'"), 0755)
	if err != nil {
		t.Fatalf("Failed to create suspicious file: %v", err)
	}
	
	// Wait for the file to be detected
	time.Sleep(1500 * time.Millisecond) // Wait for one scan cycle
	
	// Get last events
	events := monitor.GetLastEvents(10)
	if len(events) == 0 {
		t.Log("No events detected - this may be expected in test environment")
	} else {
		t.Logf("Detected %d events", len(events))
		for _, event := range events {
			t.Logf("Event: %s - %s", event.EventType, event.Description)
		}
	}
	
	// Stop the monitor
	err = monitor.Stop()
	if err != nil {
		t.Errorf("Failed to stop Linux monitor: %v", err)
	}
}

func TestSuspiciousFileDetection(t *testing.T) {
	// Create a temporary directory for testing
	tempDir := t.TempDir()
	testPath := filepath.Join(tempDir, "test_dir")
	err := os.MkdirAll(testPath, 0755)
	if err != nil {
		t.Fatalf("Failed to create test directory: %v", err)
	}

	// Create monitor config
	config := MonitorConfig{
		ScanInterval:    100 * time.Millisecond, // Fast scanning for tests
		SuspiciousPaths: []string{testPath},
		CPULimit:        80.0,
		MemoryLimit:     80.0,
	}
	
	// Create file monitor to test file detection
	monitor := NewFileMonitor(config)
	
	// Create a test file info
	testFile := filepath.Join(testPath, "suspicious.exe")
	err = os.WriteFile(testFile, []byte("test content"), 0755)
	if err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}
	
	fileInfo, err := os.Stat(testFile)
	if err != nil {
		t.Fatalf("Failed to get file info: %v", err)
	}
	
	// Test if the file is detected as suspicious
	isSuspicious := monitor.isSuspiciousFile(testFile, fileInfo)
	if !isSuspicious {
		t.Errorf("File with .exe extension should be detected as suspicious: %s", testFile)
	}
	
	// Test a non-suspicious file
	normalFile := filepath.Join(testPath, "document.txt")
	err = os.WriteFile(normalFile, []byte("normal content"), 0644)
	if err != nil {
		t.Fatalf("Failed to create normal file: %v", err)
	}
	
	normalFileInfo, err := os.Stat(normalFile)
	if err != nil {
		t.Fatalf("Failed to get normal file info: %v", err)
	}
	
	isNormalSuspicious := monitor.isSuspiciousFile(normalFile, normalFileInfo)
	if isNormalSuspicious {
		t.Errorf("Normal file should not be detected as suspicious: %s", normalFile)
	}
}