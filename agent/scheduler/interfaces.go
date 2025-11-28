package scheduler

import "time"

// Job represents a scheduled task
type Job interface {
	ID() string
	Name() string
	Run() error
	Schedule() string // Cron-like expression
	LastRun() time.Time
	NextRun() time.Time
}

// JobFunc is a function that can be scheduled
type JobFunc func() error

func (jf JobFunc) Run() error {
	return jf()
}

// Scheduler defines the interface for scheduling jobs
type Scheduler interface {
	// Schedule a job to run at specific intervals
	Schedule(job Job) error
	
	// Schedule a function to run at specific intervals
	ScheduleFunc(name string, schedule string, job JobFunc) error
	
	// Start the scheduler
	Start() error
	
	// Stop the scheduler
	Stop() error
	
	// Get all scheduled jobs
	Jobs() []Job
	
	// Remove a job by ID
	Remove(jobID string) error
	
	// Check if scheduler is running
	IsRunning() bool
}