package task

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestScheduler(t *testing.T) {
	t.Run("runs task immediately and stops", func(t *testing.T) {
		var (
			mu       sync.Mutex
			runCount int
		)

		task := func(ctx context.Context) error {
			mu.Lock()
			runCount++
			mu.Unlock()
			return nil
		}

		// Schedule task for far in the future to ensure only initial run happens
		scheduler := NewScheduler(task, "23:59")
		go scheduler.Start()

		// Wait a bit for initial run
		time.Sleep(50 * time.Millisecond)

		scheduler.Stop()

		mu.Lock()
		assert.Equal(t, 1, runCount, "Task should run exactly once (initial run)")
		mu.Unlock()
	})

	t.Run("respects context cancellation", func(t *testing.T) {
		done := make(chan struct{})
		task := func(ctx context.Context) error {
			<-ctx.Done() // Block until context is cancelled
			close(done)
			return ctx.Err()
		}

		scheduler := NewScheduler(task, "23:59")
		go scheduler.Start()

		// Wait a bit for task to start
		time.Sleep(50 * time.Millisecond)

		scheduler.Stop()

		// Verify task was cancelled
		select {
		case <-done:
			// Success - task responded to cancellation
		case <-time.After(time.Second):
			t.Fatal("Task did not respond to cancellation")
		}
	})

	t.Run("runs scheduled task", func(t *testing.T) {
		var (
			mu       sync.Mutex
			runCount int
			done     = make(chan struct{})
		)

		task := func(ctx context.Context) error {
			mu.Lock()
			runCount++
			if runCount == 2 {
				close(done)
			}
			mu.Unlock()
			return nil
		}

		// Get current minute and schedule for the next one
		now := time.Now()
		nextMinute := now.Add(time.Minute).Truncate(time.Minute)
		scheduler := NewScheduler(task, nextMinute.Format("15:04"))
		go scheduler.Start()

		// Wait for initial run
		time.Sleep(50 * time.Millisecond)

		mu.Lock()
		initialRuns := runCount
		mu.Unlock()
		assert.Equal(t, 1, initialRuns, "Should have one initial run")

		// Wait for scheduled run or timeout
		select {
		case <-done:
			// Success - scheduled run completed
		case <-time.After(70 * time.Second):
			t.Fatal("Timed out waiting for scheduled run")
		}

		scheduler.Stop()

		mu.Lock()
		assert.Equal(t, 2, runCount, "Should have one scheduled run after initial run")
		mu.Unlock()
	})
}

func TestParseTime(t *testing.T) {
	tests := []struct {
		name    string
		timeStr string
		wantErr bool
	}{
		{
			name:    "valid 24-hour time",
			timeStr: "13:45",
			wantErr: false,
		},
		{
			name:    "valid 12-hour time PM",
			timeStr: "1:45PM",
			wantErr: false,
		},
		{
			name:    "invalid format",
			timeStr: "25:00",
			wantErr: true,
		},
		{
			name:    "garbage input",
			timeStr: "not a time",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseTime(tt.timeStr)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
