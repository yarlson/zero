package task

import (
	"context"
	"fmt"
	"log"
	"time"
)

// Scheduler handles the scheduling and execution of periodic tasks
type Scheduler struct {
	task   func(context.Context) error
	time   string
	ctx    context.Context
	cancel context.CancelFunc
}

// NewScheduler creates a new cron Scheduler
func NewScheduler(task func(context.Context) error, time string) *Scheduler {
	ctx, cancel := context.WithCancel(context.Background())
	return &Scheduler{
		task:   task,
		time:   time,
		ctx:    ctx,
		cancel: cancel,
	}
}

// Start begins the cron service
func (s *Scheduler) Start() {
	renewalTime, err := ParseTime(s.time)
	if err != nil {
		log.Fatalf("Invalid time format: %v", err)
	}

	log.Printf("Starting service. Daily task scheduled at %s", renewalTime.Format("15:04"))

	// Initial run
	if err := s.task(s.ctx); err != nil {
		log.Printf("Initial task run failed: %v", err)
	}

	// Setup daily checks
	ticker := time.NewTicker(getNextTickDuration(renewalTime))
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			log.Println("Running scheduled task")
			if err := s.task(s.ctx); err != nil {
				log.Printf("Scheduled task failed: %v", err)
			}
			ticker.Reset(24 * time.Hour)
		case <-s.ctx.Done():
			return
		}
	}
}

// Stop gracefully stops the cron service
func (s *Scheduler) Stop() {
	s.cancel()
}

// ParseTime parses a time string in various formats
func ParseTime(timeStr string) (time.Time, error) {
	formats := []string{
		"15:04",
		"3:04PM",
		"3:04 PM",
	}

	for _, format := range formats {
		t, err := time.Parse(format, timeStr)
		if err == nil {
			return t, nil
		}
	}

	return time.Time{}, fmt.Errorf("unable to parse time: %s", timeStr)
}

func getNextTickDuration(t time.Time) time.Duration {
	now := time.Now()
	next := time.Date(now.Year(), now.Month(), now.Day(), t.Hour(), t.Minute(), 0, 0, now.Location())
	if next.Before(now) {
		next = next.Add(24 * time.Hour)
	}
	return next.Sub(now)
}
