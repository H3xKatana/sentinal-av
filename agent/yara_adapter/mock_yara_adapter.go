//go:build mock || disable_yara
// +build mock disable_yara

package yara_adapter

import (
	"fmt"
	"path/filepath"
	"strings"
)

// Mock types for systems without YARA library
type YaraRule struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Content     string `json:"content"`
}

type YaraMatch struct {
	RuleName    string                 `json:"rule_name"`
	RuleID      string                 `json:"rule_id"`
	Namespace   string                 `json:"namespace"`
	Tags        []string               `json:"tags"`
	Metas       map[string]interface{} `json:"metas"`
	Strings     []interface{}          `json:"strings"` // Using interface{} as placeholder
	File        string                 `json:"file"`
}

// YaraAdapter provides a mock interface to YARA scanning functionality
type YaraAdapter struct {
	rulesDir string
}

// YaraAdapterConfig holds configuration for the YARA adapter
type YaraAdapterConfig struct {
	RulesDir string // Directory containing YARA rule files
	Rules    []string // Specific rule files to load
}

// NewYaraAdapter creates a new mock YARA adapter instance
func NewYaraAdapter(config YaraAdapterConfig) (*YaraAdapter, error) {
	// In a real implementation, this would compile YARA rules
	// For this mock, we just store the configuration
	adapter := &YaraAdapter{
		rulesDir: config.RulesDir,
	}
	
	fmt.Printf("Mock YARA adapter initialized with rules directory: %s\n", config.RulesDir)
	
	return adapter, nil
}

// ScanFile simulates scanning a file with YARA rules
func (ya *YaraAdapter) ScanFile(filePath string) ([]YaraMatch, error) {
	// In a real implementation, this would scan the file with YARA rules
	// For this mock, we'll return empty results
	fmt.Printf("Mock scanning file: %s\n", filePath)
	
	// In a real implementation, this would check the file against all loaded rules
	// and return matches. For now, return an empty list.
	return []YaraMatch{}, nil
}

// ScanFileMem simulates scanning a file in memory with YARA rules
func (ya *YaraAdapter) ScanFileMem(data []byte) ([]YaraMatch, error) {
	// In a real implementation, this would scan the memory with YARA rules
	// For this mock, we'll return empty results
	fmt.Printf("Mock scanning file in memory (%d bytes)\n", len(data))
	
	return []YaraMatch{}, nil
}

// IsFileMalicious checks if a file matches any YARA rules (malicious)
func (ya *YaraAdapter) IsFileMalicious(filePath string) (bool, error) {
	// For demo purposes, we'll check for certain file extensions or content patterns
	// that might indicate malware, though this is not a real YARA scan
	
	ext := strings.ToLower(filepath.Ext(filePath))
	if ext == ".exe" || ext == ".scr" || ext == ".bat" || ext == ".cmd" {
		// Check the file name for potential malicious indicators
		baseName := strings.ToLower(filepath.Base(filePath))
		
		// These are simple heuristics, not actual YARA rules
		maliciousIndicators := []string{
			"keygen", "crack", "patch", "trojan", "virus", "malware", 
			"backdoor", "rootkit", "ransomware", "worm", "spyware",
			"adware", "bot", "miner",
		}
		
		for _, indicator := range maliciousIndicators {
			if strings.Contains(baseName, indicator) {
				return true, nil
			}
		}
	}
	
	// In a real implementation, this would scan the file with YARA rules
	// For the mock, return false to indicate the file is not malicious
	return false, nil
}

// GetRules returns the loaded YARA rules (mock implementation)
func (ya *YaraAdapter) GetRules() interface{} {
	// Return nil as placeholder since we don't have actual rules loaded
	return nil
}

// ReloadRules reloads YARA rules from the configured directory (mock implementation)
func (ya *YaraAdapter) ReloadRules() error {
	// In a real implementation, this would reload the rules from disk
	// For the mock, we just return nil to indicate success
	return nil
}

// Close cleans up resources used by the YARA adapter
func (ya *YaraAdapter) Close() error {
	// In a real implementation, this would free YARA resources
	// For the mock, there's nothing to close
	return nil
}