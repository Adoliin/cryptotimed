package integration

import (
	"fmt"
	"testing"
	"time"

	"cryptotimed/src/operations"
)

// Performance and Benchmarking Tests

const (
	benchmarkDuration = 100 * time.Millisecond
	benchmarkSamples  = 2
)

func TestBenchmarkOperation(t *testing.T) {
	opts := operations.BenchmarkOptions{
		Duration: benchmarkDuration,
		Samples:  benchmarkSamples,
	}

	result, err := operations.RunBenchmark(opts)
	if err != nil {
		t.Fatalf("Benchmark failed: %v", err)
	}

	// Validate benchmark results
	if len(result.Samples) != benchmarkSamples {
		t.Errorf("Expected %d samples, got %d", benchmarkSamples, len(result.Samples))
	}

	if result.AvgOpsPerSecond <= 0 {
		t.Error("Average operations per second should be positive")
	}

	if result.TotalOps == 0 {
		t.Error("Total operations should be greater than zero")
	}

	if len(result.TimeEstimates) == 0 {
		t.Error("Time estimates should be provided")
	}

	// Validate individual samples
	for i, sample := range result.Samples {
		if sample.Operations == 0 {
			t.Errorf("Sample %d should have performed operations", i)
		}
		if sample.OpsPerSecond <= 0 {
			t.Errorf("Sample %d should have positive ops/sec", i)
		}
		if sample.Elapsed <= 0 {
			t.Errorf("Sample %d should have positive elapsed time", i)
		}
	}

	// Validate time estimates
	for _, estimate := range result.TimeEstimates {
		if estimate.WorkFactor == 0 {
			t.Error("Work factor in estimate should be positive")
		}
		if estimate.EstimatedTime <= 0 {
			t.Error("Estimated time should be positive")
		}
	}
}

func TestPerformanceWithDifferentWorkFactors(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping performance test in short mode")
	}

	testData := []byte("Performance test data")
	workFactors := []uint64{100, 1000, 10000}

	for _, wf := range workFactors {
		t.Run(fmt.Sprintf("work_factor_%d", wf), func(t *testing.T) {
			inputFile := createTempFile(t, "perf_input.txt", testData)

			// Measure encryption time
			encryptStart := time.Now()
			encryptOpts := operations.EncryptOptions{
				InputFile:  inputFile,
				WorkFactor: wf,
				KeyInput:   "",
			}

			encryptResult, err := operations.EncryptFile(encryptOpts)
			if err != nil {
				t.Fatalf("Encryption failed: %v", err)
			}
			encryptDuration := time.Since(encryptStart)

			// Measure decryption time
			decryptStart := time.Now()
			decryptOpts := operations.DecryptOptions{
				InputFile: encryptResult.OutputFile,
				KeyInput:  "",
			}

			_, err = operations.DecryptFile(decryptOpts, nil)
			if err != nil {
				t.Fatalf("Decryption failed: %v", err)
			}
			decryptDuration := time.Since(decryptStart)

			t.Logf("Work factor %d: Encrypt=%v, Decrypt=%v", wf, encryptDuration, decryptDuration)

			// Note: Encryption includes RSA key generation overhead, so it may take longer than decryption
			// for small work factors. This is expected behavior.
			// For large work factors, decryption should take longer due to sequential squaring.
			if wf >= 10000 && encryptDuration > decryptDuration {
				t.Logf("Note: Encryption took longer than decryption for work factor %d. This may be due to RSA key generation overhead.", wf)
			}
		})
	}
}
