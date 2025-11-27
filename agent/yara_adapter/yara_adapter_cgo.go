//go:build !mock && !disable_yara
// +build !mock,!disable_yara

package yara_adapter

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/hillu/go-yara/v4"
)

// YaraRule represents a YARA rule
type YaraRule struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Content     string `json:"content"`
}

// YaraMatch represents a match found by YARA
type YaraMatch struct {
	RuleName    string                 `json:"rule_name"`
	RuleID      string                 `json:"rule_id"`
	Namespace   string                 `json:"namespace"`
	Tags        []string               `json:"tags"`
	Metas       map[string]interface{} `json:"metas"`
	Strings     []yara.MatchString     `json:"strings"`
	File        string                 `json:"file"`
}

// YaraAdapter provides an interface to YARA scanning functionality
type YaraAdapter struct {
	compiler    *yara.Compiler
	rules       *yara.Rules
	initialized bool
	mu          sync.RWMutex
	rulesDir    string
}

// YaraAdapterConfig holds configuration for the YARA adapter
type YaraAdapterConfig struct {
	RulesDir string // Directory containing YARA rule files
	Rules    []string // Specific rule files to load
}

// NewYaraAdapter creates a new YARA adapter instance
func NewYaraAdapter(config YaraAdapterConfig) (*YaraAdapter, error) {
	adapter := &YaraAdapter{
		rulesDir: config.RulesDir,
	}

	// Initialize YARA compiler
	compiler, err := yara.NewCompiler()
	if err != nil {
		return nil, fmt.Errorf("failed to create YARA compiler: %v", err)
	}

	// Load rules
	var ruleFiles []string
	if config.RulesDir != "" {
		// Load all .yar and .yara files from the rules directory
		files, err := filepath.Glob(filepath.Join(config.RulesDir, "*.yar"))
		if err != nil {
			return nil, fmt.Errorf("failed to find YARA rule files in directory: %v", err)
		}
		ruleFiles = append(ruleFiles, files...)

		moreFiles, err := filepath.Glob(filepath.Join(config.RulesDir, "*.yara"))
		if err != nil {
			return nil, fmt.Errorf("failed to find YARA rule files in directory: %v", err)
		}
		ruleFiles = append(ruleFiles, moreFiles...)
	}

	// Add any specific rule files provided in config
	ruleFiles = append(ruleFiles, config.Rules...)

	// Compile all rule files
	for _, ruleFile := range ruleFiles {
		content, err := os.ReadFile(ruleFile)
		if err != nil {
			compiler.Destroy()
			return nil, fmt.Errorf("failed to read rule file %s: %v", ruleFile, err)
		}

		err = compiler.AddString(string(content), ruleFile)
		if err != nil {
			compiler.Destroy()
			return nil, fmt.Errorf("failed to compile rule file %s: %v", ruleFile, err)
		}
	}

	// Compile the rules into executable form
	rules, err := compiler.GetRules()
	if err != nil {
		compiler.Destroy()
		return nil, fmt.Errorf("failed to compile rules: %v", err)
	}

	adapter.compiler = compiler
	adapter.rules = rules
	adapter.initialized = true

	return adapter, nil
}

// ScanFile scans a single file with YARA rules
func (ya *YaraAdapter) ScanFile(filePath string) ([]YaraMatch, error) {
	ya.mu.RLock()
	defer ya.mu.RUnlock()

	if !ya.initialized {
		return nil, fmt.Errorf("YARA adapter not initialized")
	}

	var matches []YaraMatch

	callbackFunc := func(result yara.CallbackMsg) int {
		switch result.Message {
		case yara.MatchFound:
			m := result.Match
			yaraMatch := YaraMatch{
				RuleName:  m.Rule,
				Namespace: m.Namespace,
				Tags:      m.Tags,
				Metas:     make(map[string]interface{}),
				Strings:   m.Strings,
				File:      filePath,
			}

			// Convert metadata
			for _, meta := range m.Metas {
				yaraMatch.Metas[meta.Id] = meta.Value
			}

			matches = append(matches, yaraMatch)
		}
		return yara.Continue
	}

	// Scan the file using our callback function
	err := ya.rules.ScanFile(filePath, 0, yara.MatchAll, callbackFunc)
	if err != nil {
		return nil, fmt.Errorf("YARA scan failed for file %s: %v", filePath, err)
	}

	return matches, nil
}

// ScanFileMem scans a file in memory with YARA rules
func (ya *YaraAdapter) ScanFileMem(data []byte) ([]YaraMatch, error) {
	ya.mu.RLock()
	defer ya.mu.RUnlock()

	if !ya.initialized {
		return nil, fmt.Errorf("YARA adapter not initialized")
	}

	var matches []YaraMatch

	callbackFunc := func(result yara.CallbackMsg) int {
		switch result.Message {
		case yara.MatchFound:
			m := result.Match
			yaraMatch := YaraMatch{
				RuleName:  m.Rule,
				Namespace: m.Namespace,
				Tags:      m.Tags,
				Metas:     make(map[string]interface{}),
				Strings:   m.Strings,
				File:      "memory",
			}

			// Convert metadata
			for _, meta := range m.Metas {
				yaraMatch.Metas[meta.Id] = meta.Value
			}

			matches = append(matches, yaraMatch)
		}
		return yara.Continue
	}

	// Scan the memory using our callback function
	err := ya.rules.ScanMem(data, 0, yara.MatchAll, callbackFunc)
	if err != nil {
		return nil, fmt.Errorf("YARA scan failed in memory: %v", err)
	}

	return matches, nil
}

// IsFileMalicious checks if a file matches any YARA rules (malicious)
func (ya *YaraAdapter) IsFileMalicious(filePath string) (bool, error) {
	matches, err := ya.ScanFile(filePath)
	if err != nil {
		return false, err
	}

	// Check if any of the matched rules are considered malicious
	// This assumes that rules related to malware will have certain tags or naming conventions
	for _, match := range matches {
		// Check if the rule has tags that indicate maliciousness
		for _, tag := range match.Tags {
			if isMaliciousTag(tag) {
				return true, nil
			}
		}

		// Check if the rule name pattern indicates maliciousness
		if isMaliciousRuleName(match.RuleName) {
			return true, nil
		}

		// Check metadata for indicators of maliciousness
		for key, value := range match.Metas {
			if isMaliciousMetadata(key, value) {
				return true, nil
			}
		}
	}

	return len(matches) > 0, nil // Return true if any rule matched
}

// isMaliciousTag checks if a tag suggests malicious content
func isMaliciousTag(tag string) bool {
	maliciousTags := []string{
		"malware", "trojan", "virus", "adware", "ransomware",
		"rootkit", "backdoor", "exploit", "attack", "pup",
		"keylogger", "infostealer", "cryptominer", "botnet",
	}

	for _, mtag := range maliciousTags {
		if strings.Contains(strings.ToLower(tag), mtag) {
			return true
		}
	}
	return false
}

// isMaliciousRuleName checks if a rule name suggests malicious content
func isMaliciousRuleName(name string) bool {
	maliciousPatterns := []string{
		"malware", "trojan", "virus", "adware", "ransomware",
		"rootkit", "backdoor", "exploit", "attack", "pup",
		"keylogger", "infostealer", "cryptominer", "botnet",
		"postr", "apt", "cve", "exploit_kit",
	}

	for _, pattern := range maliciousPatterns {
		if strings.Contains(strings.ToLower(name), pattern) {
			return true
		}
	}
	return false
}

// isMaliciousMetadata checks if metadata suggests malicious content
func isMaliciousMetadata(key string, value interface{}) bool {
	key = strings.ToLower(key)
	
	// Check if the key is related to threat information
	maliciousKeys := []string{"threat", "family", "description", "reference", "author"}
	for _, mkey := range maliciousKeys {
		if strings.Contains(key, mkey) {
			// If the value contains known malicious indicators
			if valStr, ok := value.(string); ok {
				valStr = strings.ToLower(valStr)
				maliciousIndicators := []string{
					"malware", "trojan", "virus", "adware", "ransomware",
					"rootkit", "backdoor", "exploit", "attack", "pup",
					"keylogger", "infostealer", "cryptominer", "botnet",
				}
				
				for _, indicator := range maliciousIndicators {
					if strings.Contains(valStr, indicator) {
						return true
					}
				}
			}
		}
	}
	return false
}

// GetRules returns the loaded YARA rules
func (ya *YaraAdapter) GetRules() *yara.Rules {
	ya.mu.RLock()
	defer ya.mu.RUnlock()
	return ya.rules
}

// ReloadRules reloads YARA rules from the configured directory
func (ya *YaraAdapter) ReloadRules() error {
	ya.mu.Lock()
	defer ya.mu.Unlock()

	if !ya.initialized {
		return fmt.Errorf("YARA adapter not initialized")
	}

	// Create a new compiler
	newCompiler, err := yara.NewCompiler()
	if err != nil {
		return fmt.Errorf("failed to create YARA compiler: %v", err)
	}

	// Determine which rule files to load
	var ruleFiles []string
	if ya.rulesDir != "" {
		// Load all .yar and .yara files from the rules directory
		files, err := filepath.Glob(filepath.Join(ya.rulesDir, "*.yar"))
		if err != nil {
			newCompiler.Destroy()
			return fmt.Errorf("failed to find YARA rule files in directory: %v", err)
		}
		ruleFiles = append(ruleFiles, files...)

		moreFiles, err := filepath.Glob(filepath.Join(ya.rulesDir, "*.yara"))
		if err != nil {
			newCompiler.Destroy()
			return fmt.Errorf("failed to find YARA rule files in directory: %v", err)
		}
		ruleFiles = append(ruleFiles, moreFiles...)
	}

	// Compile all rule files
	for _, ruleFile := range ruleFiles {
		content, err := os.ReadFile(ruleFile)
		if err != nil {
			newCompiler.Destroy()
			return fmt.Errorf("failed to read rule file %s: %v", ruleFile, err)
		}

		err = newCompiler.AddString(string(content), ruleFile)
		if err != nil {
			newCompiler.Destroy()
			return fmt.Errorf("failed to compile rule file %s: %v", ruleFile, err)
		}
	}

	// Compile the rules into executable form
	newRules, err := newCompiler.GetRules()
	if err != nil {
		newCompiler.Destroy()
		return fmt.Errorf("failed to compile rules: %v", err)
	}

	// Replace old rules with new ones
	oldRules := ya.rules
	oldCompiler := ya.compiler
	
	ya.rules = newRules
	ya.compiler = newCompiler

	// Clean up old resources
	oldRules.Destroy()
	oldCompiler.Destroy()

	return nil
}

// Close cleans up resources used by the YARA adapter
func (ya *YaraAdapter) Close() error {
	ya.mu.Lock()
	defer ya.mu.Unlock()

	if !ya.initialized {
		return nil
	}

	if ya.rules != nil {
		ya.rules.Destroy()
		ya.rules = nil
	}
	
	if ya.compiler != nil {
		ya.compiler.Destroy()
		ya.compiler = nil
	}
	
	ya.initialized = false

	return nil
}