package utils

import (
	"testing"
	"time"
)

func TestProgressBar(t *testing.T) {
	// Test basic progress bar functionality
	pb := NewProgressBar(100)

	if pb.total != 100 {
		t.Errorf("Expected total=100, got %d", pb.total)
	}
	if pb.current != 0 {
		t.Errorf("Expected current=0, got %d", pb.current)
	}
	if pb.width != 50 {
		t.Errorf("Expected width=50, got %d", pb.width)
	}

	// Test update
	pb.Update(50)
	if pb.current != 50 {
		t.Errorf("Expected current=50 after update, got %d", pb.current)
	}

	// Test finish
	pb.Finish()
	if pb.current != pb.total {
		t.Errorf("Expected current=total after finish, got %d", pb.current)
	}
}

func TestEstimateTime(t *testing.T) {
	// Test basic time estimation
	operations := uint64(1000)
	opsPerSecond := 100.0

	estimated := EstimateTime(operations, opsPerSecond)
	expected := 10 * time.Second

	if estimated != expected {
		t.Errorf("Expected %v, got %v", expected, estimated)
	}

	// Test zero rate
	estimated = EstimateTime(operations, 0)
	if estimated != 0 {
		t.Errorf("Expected 0 for zero rate, got %v", estimated)
	}

	// Test negative rate
	estimated = EstimateTime(operations, -10)
	if estimated != 0 {
		t.Errorf("Expected 0 for negative rate, got %v", estimated)
	}
}

func TestFormatDuration(t *testing.T) {
	tests := []struct {
		duration time.Duration
		expected string
	}{
		{30 * time.Second, "30.0s"},
		{90 * time.Second, "1.5m"},
		{2 * time.Hour, "2.0h"},
		{25 * time.Hour, "1.0d"},
		{48 * time.Hour, "2.0d"},
	}

	for _, test := range tests {
		result := FormatDuration(test.duration)
		if result != test.expected {
			t.Errorf("FormatDuration(%v) = %s, want %s", test.duration, result, test.expected)
		}
	}
}

func TestProgressBarUpdate(t *testing.T) {
	// Test that rapid updates don't cause issues
	pb := NewProgressBar(1000)

	for i := uint64(0); i <= 1000; i += 100 {
		pb.Update(i)
		if pb.current != i {
			t.Errorf("Expected current=%d, got %d", i, pb.current)
		}
	}

	// Test update beyond total
	pb.Update(1500)
	if pb.current != 1500 {
		t.Errorf("Expected current=1500, got %d", pb.current)
	}
}

func TestNewProgressBar(t *testing.T) {
	// Test different total values
	totals := []uint64{1, 100, 1000000}

	for _, total := range totals {
		pb := NewProgressBar(total)
		if pb.total != total {
			t.Errorf("Expected total=%d, got %d", total, pb.total)
		}
		if pb.current != 0 {
			t.Errorf("Expected current=0, got %d", pb.current)
		}
	}
}
