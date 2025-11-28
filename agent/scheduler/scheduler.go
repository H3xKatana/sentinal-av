package scheduler

import (
	"errors"
	"fmt"
	"log"
	"math/rand"
	"strings"
	"sync"
	"time"
)

// InMemoryJob represents a job with in-memory storage
type InMemoryJob struct {
	id        string
	name      string
	jobFunc   JobFunc
	schedule  string
	lastRun   time.Time
	nextRun   time.Time
	interval  time.Duration // For simple interval-based scheduling
	stopChan  chan struct{}
	mu        sync.RWMutex
}

// NewInMemoryJob creates a new in-memory job
func NewInMemoryJob(name string, schedule string, jobFunc JobFunc) *InMemoryJob {
	job := &InMemoryJob{
		id:       generateJobID(),
		name:     name,
		jobFunc:  jobFunc,
		schedule: schedule,
		stopChan: make(chan struct{}),
	}

	// Parse schedule and calculate next run time
	job.calculateNextRun()

	return job
}

// Run executes the job function
func (ij *InMemoryJob) Run() error {
	ij.mu.Lock()
	defer ij.mu.Unlock()

	return ij.jobFunc()
}

// generateJobID creates a unique ID for the job
func generateJobID() string {
	return fmt.Sprintf("job_%d_%d", time.Now().UnixNano(), rand.Intn(10000))
}

// parseSchedule parses the schedule string to determine interval (simplified cron-like)
func parseSchedule(schedule string) (time.Duration, error) {
	// For now, we'll support simple interval formats like "@every 5m", "@hourly", "@daily"
	// and basic cron-like expressions
	switch {
	case strings.HasPrefix(schedule, "@every "):
		intervalStr := strings.TrimPrefix(schedule, "@every ")
		duration, err := time.ParseDuration(intervalStr)
		if err != nil {
			return 0, fmt.Errorf("invalid duration format: %v", err)
		}
		return duration, nil
	case schedule == "@hourly":
		return time.Hour, nil
	case schedule == "@daily":
		return 24 * time.Hour, nil
	case schedule == "@minutely":
		return time.Minute, nil
	default:
		// For cron-like expressions, we'll do a basic check
		parts := strings.Fields(schedule)
		if len(parts) == 5 {
			// Basic validation for cron expressions - would need a more complex parser for full support
			return 0, errors.New("cron expressions not fully supported yet, use @every <duration>, @hourly, @daily, or @minutely")
		}
		return 0, errors.New("invalid schedule format")
	}
}

// calculateNextRun calculates the next run time based on schedule
func (ij *InMemoryJob) calculateNextRun() {
	ij.mu.Lock()
	defer ij.mu.Unlock()

	interval, err := parseSchedule(ij.schedule)
	if err != nil {
		log.Printf("Error parsing schedule for job %s: %v", ij.name, err)
		// Set a default interval of 1 hour for invalid schedules
		ij.interval = time.Hour
	} else {
		ij.interval = interval
	}

	ij.nextRun = time.Now().Add(ij.interval)
}

// ID returns the job ID
func (ij *InMemoryJob) ID() string {
	ij.mu.RLock()
	defer ij.mu.RUnlock()
	return ij.id
}

// Name returns the job name
func (ij *InMemoryJob) Name() string {
	ij.mu.RLock()
	defer ij.mu.RUnlock()
	return ij.name
}

// Schedule returns the schedule string
func (ij *InMemoryJob) Schedule() string {
	ij.mu.RLock()
	defer ij.mu.RUnlock()
	return ij.schedule
}

// LastRun returns the last run time
func (ij *InMemoryJob) LastRun() time.Time {
	ij.mu.RLock()
	defer ij.mu.RUnlock()
	return ij.lastRun
}

// NextRun returns the next run time
func (ij *InMemoryJob) NextRun() time.Time {
	ij.mu.RLock()
	defer ij.mu.RUnlock()
	return ij.nextRun
}

// InMemoryScheduler implements the Scheduler interface with in-memory storage
type InMemoryScheduler struct {
	jobs    map[string]*InMemoryJob
	ticker  *time.Ticker
	running bool
	mu      sync.RWMutex
	stopCh  chan struct{}
	wg      sync.WaitGroup
}

// NewInMemoryScheduler creates a new in-memory scheduler
func NewInMemoryScheduler() *InMemoryScheduler {
	return &InMemoryScheduler{
		jobs:   make(map[string]*InMemoryJob),
		stopCh: make(chan struct{}),
	}
}

// Schedule adds a job to the scheduler
func (s *InMemoryScheduler) Schedule(job Job) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Check if the job is already an InMemoryJob
	if inMemJob, ok := job.(*InMemoryJob); ok {
		s.jobs[inMemJob.ID()] = inMemJob
		return nil
	}

	// Create a new InMemoryJob that wraps the provided Job
	// For this, we create a JobFunc that calls the job's Run method
	jobFunc := JobFunc(func() error {
		return job.Run()
	})

	inMemJob := &InMemoryJob{
		id:       generateJobID(),
		name:     job.Name(),
		jobFunc:  jobFunc,
		schedule: job.Schedule(),
		stopChan: make(chan struct{}),
	}
	inMemJob.calculateNextRun()
	s.jobs[inMemJob.ID()] = inMemJob

	return nil
}

// ScheduleFunc creates and schedules a function as a job
func (s *InMemoryScheduler) ScheduleFunc(name string, schedule string, job JobFunc) error {
	jobObj := NewInMemoryJob(name, schedule, job)
	return s.Schedule(jobObj)
}

// Start begins the scheduler
func (s *InMemoryScheduler) Start() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.running {
		return errors.New("scheduler is already running")
	}

	s.running = true
	s.ticker = time.NewTicker(10 * time.Second) // Check every 10 seconds for scheduled jobs

	s.wg.Add(1)
	go s.run()

	return nil
}

// run is the main scheduler loop
func (s *InMemoryScheduler) run() {
	defer s.wg.Done()

	for {
		select {
		case <-s.ticker.C:
			s.executeDueJobs()
		case <-s.stopCh:
			s.ticker.Stop()
			return
		}
	}
}

// executeDueJobs runs all jobs that are due
func (s *InMemoryScheduler) executeDueJobs() {
	s.mu.RLock()
	defer s.mu.RUnlock()

	now := time.Now()

	for _, job := range s.jobs {
		job.mu.Lock()
		if now.After(job.nextRun) {
			// Update last run and calculate next run
			job.lastRun = now
			job.nextRun = now.Add(job.interval)
			job.mu.Unlock()

			// Run the job in a goroutine so it doesn't block the scheduler
			go func(j *InMemoryJob) {
				if err := j.Run(); err != nil {
					log.Printf("Error running job %s: %v", j.Name(), err)
				}
			}(job)
		} else {
			job.mu.Unlock()
		}
	}
}

// Stop stops the scheduler
func (s *InMemoryScheduler) Stop() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.running {
		return errors.New("scheduler is not running")
	}

	close(s.stopCh)
	s.running = false
	s.wg.Wait() // Wait for the run goroutine to finish

	return nil
}

// Jobs returns all scheduled jobs
func (s *InMemoryScheduler) Jobs() []Job {
	s.mu.RLock()
	defer s.mu.RUnlock()

	jobs := make([]Job, 0, len(s.jobs))
	for _, job := range s.jobs {
		jobs = append(jobs, job)
	}

	return jobs
}

// Remove removes a job by ID
func (s *InMemoryScheduler) Remove(jobID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.jobs[jobID]; !exists {
		return fmt.Errorf("job with ID %s does not exist", jobID)
	}

	delete(s.jobs, jobID)
	return nil
}

// IsRunning returns whether the scheduler is running
func (s *InMemoryScheduler) IsRunning() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.running
}