//go:build mock || disable_yara
// +build mock disable_yara

package yara_adapter

import (
	"fmt"
	"io/fs"
	"log"
	"path/filepath"
)

// YaraScanner implements the Scanner interface using YARA
type YaraScanner struct {
	adapter *YaraAdapter
}

// NewYaraScanner creates a new YARA-based scanner
func NewYaraScanner(adapter *YaraAdapter) *YaraScanner {
	return &YaraScanner{
		adapter: adapter,
	}
}

// ScanPath scans a directory or single file using YARA
func (ys *YaraScanner) ScanPath(path string) ([]string, error) {
	malicious := []string{}

	// Walk through the directory/file
	err := filepath.WalkDir(path, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			log.Printf("Error accessing path %s: %v", p, err)
			return nil // Continue with other files
		}

		// Only scan files, not directories
		if !d.IsDir() {
			isMalicious, err := ys.adapter.IsFileMalicious(p)
			if err != nil {
				log.Printf("Error scanning file %s: %v", p, err)
				// Continue with other files
				return nil
			}

			if isMalicious {
				malicious = append(malicious, p)
				log.Printf("Malicious file detected by YARA: %s", p)
			} else {
				log.Printf("File is clean: %s", p)
			}
		}

		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("error walking through path %s: %v", path, err)
	}

	return malicious, nil
}