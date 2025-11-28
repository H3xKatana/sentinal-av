package scheduler

import (
	"testing"
	"time"
)

func TestInMemoryScheduler(t *testing.T) {
	scheduler := NewInMemoryScheduler()

	// Test starting the scheduler
	err := scheduler.Start()
	if err != nil {
		t.Fatalf("Failed to start scheduler: %v", err)
	}

	// Verify scheduler is running
	if !scheduler.IsRunning() {
		t.Error("Scheduler should be running after Start()")
	}

	// Test scheduling a job
	jobRunCount := 0
	jobFunc := func() error {
		jobRunCount++
		return nil
	}

	err = scheduler.ScheduleFunc("test-job", "@every 1s", jobFunc)
	if err != nil {
		t.Fatalf("Failed to schedule job: %v", err)
	}

	// Verify job exists
	jobs := scheduler.Jobs()
	if len(jobs) != 1 {
		t.Errorf("Expected 1 job, got %d", len(jobs))
	}

	// Test removing a job
	jobID := jobs[0].ID()
	err = scheduler.Remove(jobID)
	if err != nil {
		t.Errorf("Failed to remove job: %v", err)
	}

	// Verify job is removed
	jobs = scheduler.Jobs()
	if len(jobs) != 0 {
		t.Errorf("Expected 0 jobs after removal, got %d", len(jobs))
	}

	// Test stopping the scheduler
	err = scheduler.Stop()
	if err != nil {
		t.Fatalf("Failed to stop scheduler: %v", err)
	}

	// Verify scheduler is not running
	if scheduler.IsRunning() {
		t.Error("Scheduler should not be running after Stop()")
	}
}

func TestInMemoryJob(t *testing.T) {
	jobRunCount := 0
	jobFunc := func() error {
		jobRunCount++
		return nil
	}

	job := NewInMemoryJob("test-job", "@every 1m", jobFunc)

	// Test job properties
	if job.Name() != "test-job" {
		t.Errorf("Expected job name 'test-job', got '%s'", job.Name())
	}

	if job.Schedule() != "@every 1m" {
		t.Errorf("Expected schedule '@every 1m', got '%s'", job.Schedule())
	}

	// Test running the job
	err := job.Run()
	if err != nil {
		t.Errorf("Job run failed: %v", err)
	}

	if jobRunCount != 1 {
		t.Errorf("Expected job to run once, ran %d times", jobRunCount)
	}
}

func TestParseSchedule(t *testing.T) {
	tests := []struct {
		schedule string
		expected time.Duration
		hasError bool
	}{
		{"@every 5m", 5 * time.Minute, false},
		{"@hourly", time.Hour, false},
		{"@daily", 24 * time.Hour, false},
		{"@minutely", time.Minute, false},
		{"invalid", 0, true},
	}

	for _, test := range tests {
		duration, err := parseSchedule(test.schedule)
		if test.hasError {
			if err == nil {
				t.Errorf("Expected error for schedule '%s', got none", test.schedule)
			}
		} else {
			if err != nil {
				t.Errorf("Unexpected error for schedule '%s': %v", test.schedule, err)
			} else if duration != test.expected {
				t.Errorf("For schedule '%s', expected duration %v, got %v", test.schedule, test.expected, duration)
			}
		}
	}
}