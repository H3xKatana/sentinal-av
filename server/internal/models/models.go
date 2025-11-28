package models

import (
	"database/sql/driver"
	"encoding/json"
	"fmt"
	"time"

	"gorm.io/gorm"
)

// StringArray is a custom type to handle string arrays (compatible with SQLite)
type StringArray []string

// Scan implements the Scanner interface for StringArray
func (s *StringArray) Scan(value interface{}) error {
	if value == nil {
		*s = nil
		return nil
	}

	switch v := value.(type) {
	case []byte:
		return json.Unmarshal(v, s)
	case string:
		return json.Unmarshal([]byte(v), s)
	default:
		return fmt.Errorf("cannot scan %T into StringArray", value)
	}
}

// Value implements the driver.Valuer interface for StringArray
func (s StringArray) Value() (driver.Value, error) {
	if s == nil {
		return nil, nil
	}
	return json.Marshal(s)
}

// Agent represents an endpoint agent in the system
type Agent struct {
	ID           uint           `json:"id" gorm:"primaryKey"`
	AgentID      string         `json:"agent_id" gorm:"uniqueIndex;not null"`
	Name         string         `json:"name" gorm:"not null"`
	Hostname     string         `json:"hostname"`
	Platform     string         `json:"platform"` // linux, windows, darwin
	Version      string         `json:"version"`
	IPAddress    string         `json:"ip_address"`
	PublicKey    string         `json:"public_key"`
	LastSeen     *time.Time     `json:"last_seen"`
	RegisteredAt time.Time      `json:"registered_at"`
	IsActive     bool           `json:"is_active"`
	Quarantine   bool           `json:"quarantine"`
	Policy       string         `json:"policy"` // policy configuration
	CreatedAt    time.Time      `json:"created_at"`
	UpdatedAt    time.Time      `json:"updated_at"`
	DeletedAt    gorm.DeletedAt `json:"deleted_at" gorm:"index"`
}

// ScanResult represents the result of a scan performed by an agent
type ScanResult struct {
	ID         uint           `json:"id" gorm:"primaryKey"`
	AgentID    uint           `json:"agent_id" gorm:"index"`
	Agent      Agent          `json:"agent" gorm:"foreignKey:AgentID"`
	ScanType   string         `json:"scan_type"` // full, quick, custom, real-time
	FilePaths  StringArray    `json:"file_paths" gorm:"type:text"` // Using text for SQLite compatibility
	Threats    []Threat       `json:"threats" gorm:"foreignkey:ScanResultID"` // threats associated with this scan
	ScanTime   time.Time      `json:"scan_time"`
	Duration   int64          `json:"duration"` // in milliseconds
	Status     string         `json:"status"`   // completed, failed, in-progress
	CreatedAt  time.Time      `json:"created_at"`
	UpdatedAt  time.Time      `json:"updated_at"`
	DeletedAt  gorm.DeletedAt `json:"deleted_at" gorm:"index"`
}

// Threat represents a detected threat in a scan result
type Threat struct {
	ID           uint      `json:"id" gorm:"primaryKey"`
	ScanResultID *uint     `json:"scan_result_id,omitempty" gorm:"index"`
	AgentID      *uint     `json:"agent_id,omitempty" gorm:"index"`
	FilePath     string    `json:"file_path"`
	ThreatType   string    `json:"threat_type"`  // malware, heuristic, suspicious
	ThreatName   string    `json:"threat_name"`  // YARA rule name, hash match, etc.
	Severity     string    `json:"severity"`     // low, medium, high, critical
	ActionTaken  string    `json:"action_taken"` // quarantined, blocked, reported
	CreatedAt    time.Time `json:"created_at"`
	// Associations
	ScanResult *ScanResult `json:"scan_result,omitempty" gorm:"foreignKey:ScanResultID"`
	Agent      *Agent      `json:"agent,omitempty" gorm:"foreignKey:AgentID"`
}

// Signature represents a detection signature (YARA rule or hash)
type Signature struct {
	ID          uint           `json:"id" gorm:"primaryKey"`
	Name        string         `json:"name" gorm:"not null"`
	Type        string         `json:"type" gorm:"not null"` // yara, hash, heuristic
	Content     string         `json:"content"`              // YARA rule content or hash
	HashType    string         `json:"hash_type,omitempty"`  // md5, sha256 (for hash signatures)
	ThreatType  string         `json:"threat_type"`          // malware family, trojan, etc.
	Description string         `json:"description"`
	Version     string         `json:"version"`
	Status      string         `json:"status"` // active, inactive, deprecated
	CreatedBy   string         `json:"created_by"`
	UpdatedAt   time.Time      `json:"updated_at"`
	CreatedAt   time.Time      `json:"created_at"`
	DeletedAt   gorm.DeletedAt `json:"deleted_at" gorm:"index"`
}

// Event represents security events detected by agents
type Event struct {
	ID          uint           `json:"id" gorm:"primaryKey"`
	AgentID     uint           `json:"agent_id" gorm:"index"`
	Agent       Agent          `json:"agent" gorm:"foreignKey:AgentID"`
	EventType   string         `json:"event_type"`  // process_creation, network_connection, file_access, etc.
	EventSource string         `json:"event_source"` // agent, signature, heuristic
	Description string         `json:"description"`
	Severity    string         `json:"severity"` // info, warning, high, critical
	Data        string         `json:"data"`     // JSON string with event-specific details
	Timestamp   time.Time      `json:"timestamp"`
	CreatedAt   time.Time      `json:"created_at"`
	DeletedAt   gorm.DeletedAt `json:"deleted_at" gorm:"index"`
}

// Quarantine represents quarantined files
type Quarantine struct {
	ID             uint           `json:"id" gorm:"primaryKey"`
	AgentID        uint           `json:"agent_id" gorm:"index"`
	Agent          Agent          `json:"agent" gorm:"foreignKey:AgentID"`
	OriginalPath   string         `json:"original_path"`
	QuarantinePath string         `json:"quarantine_path"`
	ThreatName     string         `json:"threat_name"`
	FileHash       string         `json:"file_hash"`
	FileName       string         `json:"file_name"`
	FileSize       int64          `json:"file_size"`
	Status         string         `json:"status"` // quarantined, restored, deleted
	ActionBy       string         `json:"action_by"` // user who performed action
	ActionReason   string         `json:"action_reason"`
	CreatedAt      time.Time      `json:"created_at"`
	UpdatedAt      time.Time      `json:"updated_at"`
	DeletedAt      gorm.DeletedAt `json:"deleted_at" gorm:"index"`
}

// User represents a dashboard user
type User struct {
	ID        uint           `json:"id" gorm:"primaryKey"`
	Username  string         `json:"username" gorm:"uniqueIndex;not null"`
	Email     string         `json:"email" gorm:"uniqueIndex"`
	Password  string         `json:"password" gorm:"not null"` // hashed
	Role      string         `json:"role" gorm:"default:'user'"` // admin, user
	IsActive  bool           `json:"is_active" gorm:"default:true"`
	LastSeen  *time.Time     `json:"last_seen"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
	DeletedAt gorm.DeletedAt `json:"deleted_at" gorm:"index"`
}

// Command represents a command sent from the server to an agent
type Command struct {
	ID          uint           `json:"id" gorm:"primaryKey"`
	AgentID     uint           `json:"agent_id" gorm:"index"`
	Agent       Agent          `json:"agent" gorm:"foreignKey:AgentID"`
	Command     string         `json:"command"`      // scan, update, etc.
	Status      string         `json:"status"`       // pending, completed, failed
	Params      string         `json:"params"`       // JSON string of command parameters
	CreatedAt   time.Time      `json:"created_at"`
	CompletedAt *time.Time     `json:"completed_at,omitempty"`
	DeletedAt   gorm.DeletedAt `json:"deleted_at" gorm:"index"`
}

// SystemStatus represents overall system status
type SystemStatus struct {
	ID            uint      `json:"id" gorm:"primaryKey"`
	Timestamp     time.Time `json:"timestamp"`
	AgentsOnline  int       `json:"agents_online"`
	LastScanCount int       `json:"last_scan_count"`
	ThreatsDetected int     `json:"threats_detected"`
	ActiveScans   int       `json:"active_scans"`
	SystemHealth  string    `json:"system_health"` // good, warning, critical
}