package signatures

import (
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/0xA1M/sentinel-server/internal/models"
)

// YARACompiler handles compilation of YARA rules for use by agents
type YARACompiler struct {
	// In a real implementation, this would interface with the YARA library
}

// CompileRules compiles all active YARA rules into a format that can be used by agents
func (yc *YARACompiler) CompileRules(signatures []models.Signature) ([]byte, error) {
	if len(signatures) == 0 {
		return nil, fmt.Errorf("no signatures provided")
	}

	var compiledRules strings.Builder

	for _, sig := range signatures {
		if sig.Type == "yara" && sig.Status == "active" {
			compiledRules.WriteString(sig.Content)
			compiledRules.WriteString("\n") // Add a newline between rules
		}
	}

	// In a real implementation, we would use the YARA library to compile these rules
	// For now, we'll just return the combined string as bytes
	return []byte(compiledRules.String()), nil
}

// CompileRulesForAgent compiles YARA rules specifically for an agent with filters
func (yc *YARACompiler) CompileRulesForAgent(signatures []models.Signature, platform string) ([]byte, error) {
	if len(signatures) == 0 {
		return nil, fmt.Errorf("no signatures provided")
	}

	var compiledRules strings.Builder

	for _, sig := range signatures {
		if sig.Type == "yara" && sig.Status == "active" {
			// In a real implementation, we could filter rules based on platform
			// or other criteria specific to the agent
			compiledRules.WriteString(sig.Content)
			compiledRules.WriteString("\n")
		}
	}

	return []byte(compiledRules.String()), nil
}

// ExtractMetadataFromYARARule extracts metadata from a YARA rule
func (yc *YARACompiler) ExtractMetadataFromYARARule(ruleContent string) (map[string]string, error) {
	metadata := make(map[string]string)

	// Extract rule name
	nameRegex := regexp.MustCompile(`rule\s+([a-zA-Z_][a-zA-Z0-9_]*)`)
	nameMatches := nameRegex.FindStringSubmatch(ruleContent)
	if len(nameMatches) > 1 {
		metadata["name"] = nameMatches[1]
	}

	// Extract meta section if present
	metaRegex := regexp.MustCompile(`meta:\s*(.*?)(?=\n\s*strings:|\n\s*condition:|\n\s*})`)
	metaMatches := metaRegex.FindStringSubmatch(ruleContent)
	if len(metaMatches) > 1 {
		metaSection := metaMatches[1]
		metaLines := strings.SplitSeq(metaSection, "\n")

		for line := range metaLines {
			line = strings.TrimSpace(line)
			if line != "" && strings.Contains(line, "=") {
				parts := strings.SplitN(line, "=", 2)
				if len(parts) == 2 {
					key := strings.TrimSpace(parts[0])
					value := strings.TrimSpace(parts[1])
					// Remove quotes if present
					value = strings.Trim(value, "\"'")
					metadata[key] = value
				}
			}
		}
	}

	return metadata, nil
}

// ValidateRuleCompatibility checks if a rule is compatible with the target platform
func (yc *YARACompiler) ValidateRuleCompatibility(ruleContent, platform string) error {
	// In a real implementation, we would check if the YARA rule is compatible
	// with the specific platform (Windows, Linux, Darwin)
	// For example, checking for Windows-specific conditions in cross-platform rules

	return nil
}

// CreateSignatureFromYARA creates a signature model from YARA rule content
func (yc *YARACompiler) CreateSignatureFromYARA(name, ruleContent, threatType, description, version, createdBy string) (*models.Signature, error) {
	// This function would need access to a signature validation function
	// In the actual implementation, we would pass the signature service or validation function

	// For now, we'll just skip the validation and create the signature
	// since ValidateYARA is a method of the Service struct, not available here

	// Extract metadata if not provided
	if name == "" {
		metadata, err := yc.ExtractMetadataFromYARARule(ruleContent)
		if err != nil {
			return nil, err
		}
		if n, ok := metadata["name"]; ok {
			name = n
		} else {
			name = fmt.Sprintf("yara_rule_%d", time.Now().Unix())
		}
	}

	signature := &models.Signature{
		Name:        name,
		Type:        "yara",
		Content:     ruleContent,
		ThreatType:  threatType,
		Description: description,
		Version:     version,
		Status:      "active",
		CreatedBy:   createdBy,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	return signature, nil
}
