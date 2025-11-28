package scheduler

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/0xA1M/sentinel-server/internal/models"
	syncsvc "github.com/0xA1M/sentinel-server/internal/sync"
	"gorm.io/gorm"
)

// Task represents a scheduled task
type Task struct {
	ID          string
	Name        string
	Description string
	Schedule    string // Cron-like schedule
	Func        func() error
	LastRun     time.Time
	NextRun     time.Time
	Active      bool
}

// Service manages scheduled background tasks
type Service struct {
	DB         *gorm.DB
	SyncSvc    *syncsvc.Service
	tasks      map[string]*Task
	taskMutex  sync.RWMutex
	ctx        context.Context
	cancelFunc context.CancelFunc
}

// NewService creates a new scheduler service
func NewService(db *gorm.DB, syncSvc *syncsvc.Service) *Service {
	ctx, cancelFunc := context.WithCancel(context.Background())

	scheduler := &Service{
		DB:         db,
		SyncSvc:    syncSvc,
		tasks:      make(map[string]*Task),
		ctx:        ctx,
		cancelFunc: cancelFunc,
	}

	// Register default tasks
	scheduler.registerDefaultTasks()

	return scheduler
}

// registerDefaultTasks registers the default background tasks
func (s *Service) registerDefaultTasks() {
	// Agent heartbeat check - runs every 30 seconds
	s.tasks["heartbeat_check"] = &Task{
		ID:          "heartbeat_check",
		Name:        "Agent Heartbeat Check",
		Description: "Checks for agents that haven't reported in recently",
		Schedule:    "*/30 * * * * *", // Every 30 seconds
		Func:        s.checkAgentHeartbeats,
		Active:      true,
		NextRun:     time.Now().Add(30 * time.Second),
	}

	// Signature sync - runs every 5 minutes
	s.tasks["signature_sync"] = &Task{
		ID:          "signature_sync",
		Name:        "Signature Sync",
		Description: "Synchronizes signatures to all agents",
		Schedule:    "*/5 * * * *", // Every 5 minutes
		Func:        s.syncSignatures,
		Active:      true,
		NextRun:     time.Now().Add(5 * time.Minute),
	}

	// System status update - runs every minute
	s.tasks["system_status"] = &Task{
		ID:          "system_status",
		Name:        "System Status Update",
		Description: "Updates system status metrics",
		Schedule:    "* * * * *", // Every minute (at the start of each minute)
		Func:        s.updateSystemStatus,
		Active:      true,
		NextRun:     time.Now().Add(1 * time.Minute),
	}

	// Cleanup old events - runs daily at 2 AM
	s.tasks["cleanup_events"] = &Task{
		ID:          "cleanup_events",
		Name:        "Cleanup Old Events",
		Description: "Removes events older than 30 days",
		Schedule:    "0 2 * * *", // Daily at 2 AM
		Func:        s.cleanupOldEvents,
		Active:      true,
		NextRun:     calculateNextRun("0 2 * * *", time.Now()),
	}
}

// Start starts the scheduler
func (s *Service) Start() {
	log.Println("Starting scheduler...")

	// Run scheduler in a goroutine
	go s.runScheduler()
}

// Stop stops the scheduler
func (s *Service) Stop() {
	log.Println("Stopping scheduler...")
	s.cancelFunc()
}

// runScheduler runs the main scheduler loop
func (s *Service) runScheduler() {
	ticker := time.NewTicker(1 * time.Second) // Check every second
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			s.executeDueTasks()
		case <-s.ctx.Done():
			log.Println("Scheduler stopped")
			return
		}
	}
}

// executeDueTasks executes any tasks that are due
func (s *Service) executeDueTasks() {
	s.taskMutex.RLock()
	defer s.taskMutex.RUnlock()

	now := time.Now()

	for _, task := range s.tasks {
		if task.Active && now.After(task.NextRun) {
			go func(t *Task) {
				log.Printf("Executing task: %s", t.Name)

				start := time.Now()
				err := t.Func()

				duration := time.Since(start)
				t.LastRun = start
				t.NextRun = calculateNextRun(t.Schedule, now)

				if err != nil {
					log.Printf("Task %s failed after %v: %v", t.Name, duration, err)
				} else {
					log.Printf("Task %s completed successfully in %v", t.Name, duration)
				}
			}(task)
		}
	}
}

// AddTask adds a new task to the scheduler
func (s *Service) AddTask(id, name, description, schedule string, taskFunc func() error) error {
	s.taskMutex.Lock()
	defer s.taskMutex.Unlock()

	// Check if task already exists
	if _, exists := s.tasks[id]; exists {
		return fmt.Errorf("task with ID %s already exists", id)
	}

	// Add the new task
	s.tasks[id] = &Task{
		ID:          id,
		Name:        name,
		Description: description,
		Schedule:    schedule,
		Func:        taskFunc,
		Active:      true,
		NextRun:     time.Now(),
	}

	log.Printf("Added new task: %s", name)
	return nil
}

// RemoveTask removes a task from the scheduler
func (s *Service) RemoveTask(id string) error {
	s.taskMutex.Lock()
	defer s.taskMutex.Unlock()

	task, exists := s.tasks[id]
	if !exists {
		return fmt.Errorf("task with ID %s does not exist", id)
	}

	task.Active = false
	delete(s.tasks, id)

	log.Printf("Removed task: %s", task.Name)
	return nil
}

// GetTaskStatus returns the status of a specific task
func (s *Service) GetTaskStatus(id string) (*Task, error) {
	s.taskMutex.RLock()
	defer s.taskMutex.RUnlock()

	task, exists := s.tasks[id]
	if !exists {
		return nil, fmt.Errorf("task with ID %s does not exist", id)
	}

	return task, nil
}

// GetTaskList returns a list of all tasks
func (s *Service) GetTaskList() []*Task {
	s.taskMutex.RLock()
	defer s.taskMutex.RUnlock()

	tasks := make([]*Task, 0, len(s.tasks))
	for _, task := range s.tasks {
		t := *task // Copy the task
		tasks = append(tasks, &t)
	}

	return tasks
}

// checkAgentHeartbeats checks for agents that haven't reported in recently
func (s *Service) checkAgentHeartbeats() error {
	// Get agents that haven't reported in the last 5 minutes (configurable)
	timeout := 5 * time.Minute
	outdatedAgents, err := s.SyncSvc.GetOutdatedAgents(timeout)
	if err != nil {
		return fmt.Errorf("failed to get outdated agents: %v", err)
	}

	if len(outdatedAgents) > 0 {
		log.Printf("Found %d agents that haven't checked in recently", len(outdatedAgents))

		// Update their status and potentially take action
		for _, agent := range outdatedAgents {
			log.Printf("Agent %s hasn't checked in since %v", agent.AgentID, *agent.LastSeen)

			// In a real implementation, we might try to reestablish connection,
			// send an alert, or mark the agent as offline
		}
	}

	return nil
}

// syncSignatures triggers signature synchronization for all agents
func (s *Service) syncSignatures() error {
	log.Println("Starting signature sync for all agents...")

	err := s.SyncSvc.SyncAgents()
	if err != nil {
		return fmt.Errorf("failed to sync signatures: %v", err)
	}

	log.Println("Signature sync completed successfully")
	return nil
}

// updateSystemStatus updates system status metrics
func (s *Service) updateSystemStatus() error {
	// Count agents online
	var activeAgentsCount int64
	result := s.DB.Model(&models.Agent{}).Where("is_active = ?", true).Count(&activeAgentsCount)
	if result.Error != nil {
		return fmt.Errorf("failed to count active agents: %v", result.Error)
	}

	// Create or update system status record
	status := models.SystemStatus{
		AgentsOnline: int(activeAgentsCount),
		// For now, just set some placeholder values
		LastScanCount:   0,      // Would require actual count
		ThreatsDetected: 0,      // Would require actual count
		ActiveScans:     0,      // Would require tracking active scans
		SystemHealth:    "good", // Would be calculated based on metrics
		Timestamp:       time.Now(),
	}

	// Try to update the last status record or create a new one
	var existingStatus models.SystemStatus
	result = s.DB.Last(&existingStatus)
	switch result.Error {
	case nil:
		// Update the existing record
		s.DB.Model(&existingStatus).Updates(status)
	case gorm.ErrRecordNotFound:
		// Create a new record
		s.DB.Create(&status)
	default:
		return fmt.Errorf("failed to retrieve system status: %v", result.Error)
	}

	log.Printf("Updated system status: %d agents online", activeAgentsCount)
	return nil
}

// cleanupOldEvents removes events older than 30 days
func (s *Service) cleanupOldEvents() error {
	cutoffDate := time.Now().AddDate(0, 0, -30) // 30 days ago

	// In a production system, we would actually delete the old events
	// For now, we'll just log the number of events that would be cleaned up
	var oldEventCount int64
	result := s.DB.Model(&models.Event{}).Where("timestamp < ?", cutoffDate).Count(&oldEventCount)
	if result.Error != nil {
		return fmt.Errorf("failed to count old events: %v", result.Error)
	}

	log.Printf("Found %d events older than 30 days", oldEventCount)

	// Actually remove old events
	// result = s.DB.Where("timestamp < ?", cutoffDate).Delete(&models.Event{})
	// if result.Error != nil {
	//     return fmt.Errorf("failed to delete old events: %v", result.Error)
	// }

	// For now, just log that we would clean them up
	log.Printf("Would have cleaned up %d old events", oldEventCount)
	return nil
}

// calculateNextRun calculates the next run time based on the schedule
// This is a simplified implementation - a full cron implementation would be more complex
func calculateNextRun(schedule string, lastRun time.Time) time.Time {
	// For now, we'll implement a simple interval-based calculation
	// In a real implementation, you'd want a full cron parser

	switch schedule {
	case "*/30 * * * * *": // Every 30 seconds
		return lastRun.Add(30 * time.Second)
	case "*/5 * * * *": // Every 5 minutes
		return lastRun.Add(5 * time.Minute)
	case "* * * * *": // Every minute (at the start of the minute, when second is 0)
		// Advance to the start of the next minute
		return time.Date(lastRun.Year(), lastRun.Month(), lastRun.Day(), lastRun.Hour(), lastRun.Minute()+1, 0, 0, lastRun.Location())
	case "0 * * * *": // Every hour at minute 0
		// Advance to the next hour at minute 0
		next := time.Date(lastRun.Year(), lastRun.Month(), lastRun.Day(), lastRun.Hour()+1, 0, 0, 0, lastRun.Location())
		return next
	case "0 2 * * *": // Daily at 2 AM
		// Calculate next 2 AM
		next := time.Date(lastRun.Year(), lastRun.Month(), lastRun.Day(), 2, 0, 0, 0, lastRun.Location())
		if !next.After(lastRun) {
			next = next.Add(24 * time.Hour) // Next day
		}
		return next
	default:
		// Default to 1 hour if schedule is not recognized
		return lastRun.Add(1 * time.Hour)
	}
}
