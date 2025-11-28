package vt_adapter

import (
	"fmt"
	"io/fs"
	"log"
	"path/filepath"
)

// Scanner defines the interface for malware scanning
type Scanner interface {
	ScanPath(path string) ([]string, error)
}

// VTScanner implements the Scanner interface using VirusTotal
type VTScanner struct {
	adapter *VTAdapter
}

// NewVTScanner creates a new VirusTotal-based scanner
func NewVTScanner(adapter *VTAdapter) *VTScanner {
	return &VTScanner{
		adapter: adapter,
	}
}

// ScanPath scans a directory or single file using VirusTotal
func (vts *VTScanner) ScanPath(path string) ([]string, error) {
	infected := []string{}

	// Walk through the directory/file
	err := filepath.WalkDir(path, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			log.Printf("Error accessing path %s: %v", p, err)
			return nil // Continue with other files
		}

		// Only scan files, not directories
		if !d.IsDir() {
			isMalicious, err := vts.adapter.IsFileMalicious(p)
			if err != nil {
				log.Printf("Error scanning file %s: %v", p, err)
				// Continue with other files
				return nil
			}

			if isMalicious {
				infected = append(infected, p)
				log.Printf("Malicious file detected: %s", p)
			} else {
				log.Printf("File is clean: %s", p)
			}
		}

		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("error walking through path %s: %v", path, err)
	}

	return infected, nil
}