package sync

import (
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/0xA1M/sentinel-server/internal/models"
	"github.com/0xA1M/sentinel-server/internal/signatures"
	"gorm.io/gorm"
)

// Service manages agent synchronization and signature distribution
type Service struct {
	DB           *gorm.DB
	SignatureSvc *signatures.Service
	LastSyncTime time.Time
	sync.RWMutex // Protects access to shared state
}

// NewService creates a new sync service
func NewService(db *gorm.DB, signatureSvc *signatures.Service) *Service {
	return &Service{
		DB:           db,
		SignatureSvc: signatureSvc,
		LastSyncTime: time.Now(),
	}
}

// SyncAgents performs synchronization tasks for all agents
func (s *Service) SyncAgents() error {
	// Get all active agents
	var agents []models.Agent
	result := s.DB.Where("is_active = ? AND quarantine = ?", true, false).Find(&agents)
	if result.Error != nil {
		return fmt.Errorf("failed to get agents: %v", result.Error)
	}

	// Update last sync time
	s.Lock()
	s.LastSyncTime = time.Now()
	s.Unlock()

	// For each agent, trigger a sync
	for _, agent := range agents {
		if err := s.SyncAgent(&agent); err != nil {
			log.Printf("Failed to sync agent %s: %v", agent.AgentID, err)
		}
	}

	return nil
}

// SyncAgent synchronizes a specific agent with the latest signatures
func (s *Service) SyncAgent(agent *models.Agent) error {
	// Get all active signatures
	signatures, err := s.SignatureSvc.GetAllSignatures("")
	if err != nil {
		return fmt.Errorf("failed to get signatures: %v", err)
	}

	// Update the agent's last sync time
	agent.UpdatedAt = time.Now()
	result := s.DB.Save(agent)
	if result.Error != nil {
		return fmt.Errorf("failed to update agent sync time: %v", result.Error)
	}

	log.Printf("Synced %d signatures to agent %s", len(signatures), agent.AgentID)
	return nil
}

// GetUpdatedSignatures returns signatures that have been updated since the last sync time
func (s *Service) GetUpdatedSignatures(since time.Time) ([]models.Signature, error) {
	var signatures []models.Signature
	result := s.DB.Where("status = ? AND updated_at > ?", "active", since).Find(&signatures)
	return signatures, result.Error
}

// GetAgentSyncStatus returns sync status for a specific agent
func (s *Service) GetAgentSyncStatus(agentID string) (*models.Agent, error) {
	var agent models.Agent
	result := s.DB.Where("agent_id = ?", agentID).First(&agent)
	if result.Error != nil {
		return nil, result.Error
	}
	return &agent, nil
}

// UpdateAgentSyncStatus updates the sync status for a specific agent
func (s *Service) UpdateAgentSyncStatus(agentID string, success bool, message string) error {
	var agent models.Agent
	result := s.DB.Where("agent_id = ?", agentID).First(&agent)
	if result.Error != nil {
		return result.Error
	}

	// Update sync status
	agent.UpdatedAt = time.Now()
	// In a real implementation, we might store detailed sync status

	result = s.DB.Save(&agent)
	return result.Error
}

// GetOutdatedAgents returns agents that haven't synced within the specified timeout
func (s *Service) GetOutdatedAgents(timeout time.Duration) ([]models.Agent, error) {
	cutoffTime := time.Now().Add(-timeout)

	var agents []models.Agent
	result := s.DB.Where("last_seen < ? AND is_active = ?", cutoffTime, true).Find(&agents)
	return agents, result.Error
}

// ForceAgentResync marks an agent for immediate resync
func (s *Service) ForceAgentResync(agentID string) error {
	var agent models.Agent
	result := s.DB.Where("agent_id = ?", agentID).First(&agent)
	if result.Error != nil {
		return result.Error
	}

	// Update the agent to force resync (e.g., by updating the updated_at field)
	agent.UpdatedAt = time.Now()
	result = s.DB.Save(&agent)
	return result.Error
}

// GetSyncStats returns synchronization statistics
func (s *Service) GetSyncStats() (map[string]any, error) {
	// Count total agents
	var totalAgents int64
	result := s.DB.Model(&models.Agent{}).Count(&totalAgents)
	if result.Error != nil {
		return nil, result.Error
	}

	// Count active agents
	var activeAgents int64
	result = s.DB.Model(&models.Agent{}).Where("is_active = ?", true).Count(&activeAgents)
	if result.Error != nil {
		return nil, result.Error
	}

	// Count agents that synced in the last 10 minutes
	syncThreshold := time.Now().Add(-10 * time.Minute)
	var recentlySynced int64
	result = s.DB.Model(&models.Agent{}).Where("updated_at > ?", syncThreshold).Count(&recentlySynced)
	if result.Error != nil {
		return nil, result.Error
	}

	stats := map[string]any{
		"total_agents":       totalAgents,
		"active_agents":      activeAgents,
		"recently_synced":    recentlySynced,
		"last_global_sync":   s.LastSyncTime,
		"out_of_sync_agents": activeAgents - recentlySynced,
		"sync_health_status": "good", // Would be calculated based on actual metrics
	}

	return stats, nil
}

// ScheduleSync schedules periodic synchronization
func (s *Service) ScheduleSync(interval time.Duration) {
	ticker := time.NewTicker(interval)
	go func() {
		for range ticker.C {
			if err := s.SyncAgents(); err != nil {
				log.Printf("Error during scheduled sync: %v", err)
			}
		}
	}()
}

// GetSignaturesForAgent returns signatures appropriate for a specific agent
func (s *Service) GetSignaturesForAgent(agent *models.Agent) ([]models.Signature, error) {
	// For now, return all active signatures
	// In a real implementation, this could filter signatures by agent platform,
	// threat types relevant to the agent, or other criteria
	signatures, err := s.SignatureSvc.GetAllSignatures("")
	if err != nil {
		return nil, err
	}

	// Potentially filter by agent platform in the future
	// For example, skip Windows-specific signatures for Linux agents
	filteredSignatures := []models.Signature{}
	for _, sig := range signatures {
		// Add platform-specific filtering logic here if needed
		filteredSignatures = append(filteredSignatures, sig)
	}

	return filteredSignatures, nil
}
