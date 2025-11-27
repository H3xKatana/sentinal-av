//go:build mock || disable_yara
// +build mock disable_yara

package yara_adapter

import (
	"os"
	"path/filepath"
	"testing"
)

func TestYaraAdapter(t *testing.T) {
	// Create a temporary rule file for testing
	tempDir := t.TempDir()
	ruleFile := filepath.Join(tempDir, "test_rule.yar")
	
	ruleContent := `
rule TestRule {
    strings:
        $test = "test string"
    condition:
        $test
}
`
	
	err := os.WriteFile(ruleFile, []byte(ruleContent), 0644)
	if err != nil {
		t.Fatalf("Failed to create test rule file: %v", err)
	}

	// Create adapter config
	config := YaraAdapterConfig{
		Rules: []string{ruleFile},
	}

	// Create adapter
	adapter, err := NewYaraAdapter(config)
	if err != nil {
		t.Fatalf("Failed to create YARA adapter: %v", err)
	}
	defer adapter.Close()

	// Test that adapter was initialized
	if !adapter.initialized {
		t.Error("Adapter should be initialized after creation")
	}

	// Test that rules exist
	rules := adapter.GetRules()
	if rules == nil {
		t.Error("Rules should not be nil")
	}
}

func TestYaraScanner(t *testing.T) {
	// Create a temporary rule file for testing
	tempDir := t.TempDir()
	ruleFile := filepath.Join(tempDir, "test_rule.yar")
	
	ruleContent := `
rule SuspiciousTestFile {
    meta:
        description = "Test rule for suspicious file"
        author = "Sentinel-AV"
    strings:
        $test = "suspicious_content"
    condition:
        $test
}
`
	
	err := os.WriteFile(ruleFile, []byte(ruleContent), 0644)
	if err != nil {
		t.Fatalf("Failed to create test rule file: %v", err)
	}

	// Create temporary file with suspicious content
	testFile := filepath.Join(tempDir, "suspicious.txt")
	suspiciousContent := "This file contains suspicious_content that should be detected"
	err = os.WriteFile(testFile, []byte(suspiciousContent), 0644)
	if err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	// Create clean file
	cleanFile := filepath.Join(tempDir, "clean.txt")
	cleanContent := "This is a clean file without suspicious content"
	err = os.WriteFile(cleanFile, []byte(cleanContent), 0644)
	if err != nil {
		t.Fatalf("Failed to create clean file: %v", err)
	}

	// Create adapter
	config := YaraAdapterConfig{
		Rules: []string{ruleFile},
	}
	adapter, err := NewYaraAdapter(config)
	if err != nil {
		t.Fatalf("Failed to create YARA adapter: %v", err)
	}
	defer adapter.Close()

	// Create scanner
	scanner := NewYaraScanner(adapter)

	// Test scanning suspicious file
	infected, err := scanner.ScanPath(testFile)
	if err != nil {
		t.Errorf("Error scanning suspicious file: %v", err)
	}

	// The suspicious file should be detected
	found := false
	for _, file := range infected {
		if file == testFile {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("Suspicious file %s was not detected as infected", testFile)
	}

	// Test scanning clean file
	cleanInfected, err := scanner.ScanPath(cleanFile)
	if err != nil {
		t.Errorf("Error scanning clean file: %v", err)
	}

	// The clean file should not be detected
	for _, file := range cleanInfected {
		if file == cleanFile {
			t.Errorf("Clean file %s was incorrectly detected as infected", cleanFile)
		}
	}
}

func TestIsFileMalicious(t *testing.T) {
	// Create a temporary rule file for testing
	tempDir := t.TempDir()
	ruleFile := filepath.Join(tempDir, "malware_rule.yar")
	
	ruleContent := `
rule TestMalware {
    meta:
        description = "Test malware detection"
        family = "TestFamily"
        author = "Sentinel-AV"
    strings:
        $test = "malware_signature"
    condition:
        $test
}
`
	
	err := os.WriteFile(ruleFile, []byte(ruleContent), 0644)
	if err != nil {
		t.Fatalf("Failed to create test rule file: %v", err)
	}

	// Create test file with malware signature
	testFile := filepath.Join(tempDir, "test_malware.txt")
	malwareContent := "This file contains malware_signature that should trigger the rule"
	err = os.WriteFile(testFile, []byte(malwareContent), 0644)
	if err != nil {
		t.Fatalf("Failed to create test malware file: %v", err)
	}

	// Create adapter
	config := YaraAdapterConfig{
		Rules: []string{ruleFile},
	}
	adapter, err := NewYaraAdapter(config)
	if err != nil {
		t.Fatalf("Failed to create YARA adapter: %v", err)
	}
	defer adapter.Close()

	// Test if file is detected as malicious
	isMalicious, err := adapter.IsFileMalicious(testFile)
	if err != nil {
		t.Errorf("Error checking if file is malicious: %v", err)
	}

	if !isMalicious {
		t.Error("File with malware signature should be detected as malicious")
	}

	// Test a clean file
	cleanFile := filepath.Join(tempDir, "clean.txt")
	cleanContent := "This is a clean file"
	err = os.WriteFile(cleanFile, []byte(cleanContent), 0644)
	if err != nil {
		t.Fatalf("Failed to create clean file: %v", err)
	}

	isCleanMalicious, err := adapter.IsFileMalicious(cleanFile)
	if err != nil {
		t.Errorf("Error checking if clean file is malicious: %v", err)
	}

	if isCleanMalicious {
		t.Error("Clean file should not be detected as malicious")
	}
}

func TestTagsAndMetadataDetection(t *testing.T) {
	// Create a temporary rule file for testing tags
	tempDir := t.TempDir()
	ruleFile := filepath.Join(tempDir, "tag_rule.yar")
	
	ruleContent := `
rule TaggedMalware : malware trojan {
    meta:
        threat = "trojan"
        family = "GenericTrojan"
    strings:
        $test = "trojan_signature"
    condition:
        $test
}
`
	
	err := os.WriteFile(ruleFile, []byte(ruleContent), 0644)
	if err != nil {
		t.Fatalf("Failed to create test rule file: %v", err)
	}

	// Create test file
	testFile := filepath.Join(tempDir, "tagged_malware.txt")
	malwareContent := "This file contains trojan_signature"
	err = os.WriteFile(testFile, []byte(malwareContent), 0644)
	if err != nil {
		t.Fatalf("Failed to create test malware file: %v", err)
	}

	// Create adapter
	config := YaraAdapterConfig{
		Rules: []string{ruleFile},
	}
	adapter, err := NewYaraAdapter(config)
	if err != nil {
		t.Fatalf("Failed to create YARA adapter: %v", err)
	}
	defer adapter.Close()

	// Test if file is detected as malicious based on tags
	isMalicious, err := adapter.IsFileMalicious(testFile)
	if err != nil {
		t.Errorf("Error checking if file is malicious: %v", err)
	}

	if !isMalicious {
		t.Error("File with tagged rule should be detected as malicious")
	}

	// Test direct scanning to check matches
	matches, err := adapter.ScanFile(testFile)
	if err != nil {
		t.Errorf("Error scanning file: %v", err)
	}

	if len(matches) == 0 {
		t.Error("Expected matches but got none")
	} else {
		match := matches[0]
		// Check that tags are properly captured
		if len(match.Tags) == 0 {
			t.Error("Expected tags but got none")
		}

		// Check that metadata is properly captured
		if len(match.Metas) == 0 {
			t.Error("Expected metadata but got none")
		}
	}
}