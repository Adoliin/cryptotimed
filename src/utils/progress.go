package utils

import (
	"fmt"
	"time"
)

// ProgressBar represents a simple progress bar for long-running operations
type ProgressBar struct {
	total     uint64
	current   uint64
	startTime time.Time
	lastPrint time.Time
	width     int
}

// NewProgressBar creates a new progress bar
func NewProgressBar(total uint64) *ProgressBar {
	return &ProgressBar{
		total:     total,
		current:   0,
		startTime: time.Now(),
		lastPrint: time.Now(),
		width:     50,
	}
}

// Update updates the progress bar with the current progress
func (pb *ProgressBar) Update(current uint64) {
	pb.current = current

	// Only print updates every 100ms to avoid flooding the terminal
	now := time.Now()
	if now.Sub(pb.lastPrint) < 100*time.Millisecond && current < pb.total {
		return
	}
	pb.lastPrint = now

	pb.print()
}

// Finish completes the progress bar
func (pb *ProgressBar) Finish() {
	pb.current = pb.total
	pb.print()
	fmt.Println() // New line after completion
}

// print renders the progress bar to stdout
func (pb *ProgressBar) print() {
	percentage := float64(pb.current) / float64(pb.total) * 100
	filled := int(float64(pb.width) * float64(pb.current) / float64(pb.total))

	// Calculate elapsed time and ETA
	elapsed := time.Since(pb.startTime)
	var eta time.Duration
	if pb.current > 0 {
		eta = time.Duration(float64(elapsed)*(float64(pb.total)/float64(pb.current)) - float64(elapsed))
	}

	// Build progress bar string
	bar := "["
	for i := 0; i < pb.width; i++ {
		if i < filled {
			bar += "="
		} else if i == filled && filled < pb.width {
			bar += ">"
		} else {
			bar += " "
		}
	}
	bar += "]"

	// Format the output
	fmt.Printf("\r%s %.1f%% (%d/%d) Elapsed: %v ETA: %v",
		bar, percentage, pb.current, pb.total,
		elapsed.Round(time.Second), eta.Round(time.Second))
}

// EstimateTime estimates the time required for a given number of operations
// based on a benchmark rate (operations per second)
func EstimateTime(operations uint64, opsPerSecond float64) time.Duration {
	if opsPerSecond <= 0 {
		return 0
	}
	seconds := float64(operations) / opsPerSecond
	return time.Duration(seconds * float64(time.Second))
}

// FormatDuration formats a duration in a human-readable way
func FormatDuration(d time.Duration) string {
	if d < time.Minute {
		return fmt.Sprintf("%.1fs", d.Seconds())
	} else if d < time.Hour {
		return fmt.Sprintf("%.1fm", d.Minutes())
	} else if d < 24*time.Hour {
		return fmt.Sprintf("%.1fh", d.Hours())
	} else {
		days := d.Hours() / 24
		return fmt.Sprintf("%.1fd", days)
	}
}
