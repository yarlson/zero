package cron

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"
)

// Runner defines the interface for the main certificate operation
type Runner interface {
	Run() error
}

// Service handles the scheduling and execution of periodic tasks
type Service struct {
	runner Runner
	time   string
}

// New creates a new cron Service
func New(runner Runner, time string) *Service {
	return &Service{
		runner: runner,
		time:   time,
	}
}

// Start begins the cron service
func (s *Service) Start() error {
	renewalTime, err := ParseTime(s.time)
	if err != nil {
		return fmt.Errorf("parse renewal time: %w", err)
	}

	log.Printf("Starting cron mode. Daily renewal scheduled at %s", renewalTime.Format("15:04"))

	ticker := time.NewTicker(getNextTickDuration(renewalTime))
	defer ticker.Stop()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	for {
		select {
		case <-ticker.C:
			log.Println("Running scheduled renewal")
			if err := s.runner.Run(); err != nil {
				log.Printf("Error during scheduled renewal: %v", err)
			}
			ticker.Reset(24 * time.Hour)
		case <-sigChan:
			log.Println("Received interrupt signal. Shutting down...")
			return nil
		}
	}
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
