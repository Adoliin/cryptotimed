package operations

import (
	"fmt"
	"math/big"
	"time"

	"cryptotimed/src/crypto"
	"cryptotimed/src/utils"
)

// BenchmarkOptions contains all the parameters needed for benchmarking
type BenchmarkOptions struct {
	Duration time.Duration
	Samples  int
}

// BenchmarkSample represents a single benchmark sample
type BenchmarkSample struct {
	Operations   uint64
	Elapsed      time.Duration
	OpsPerSecond float64
}

// BenchmarkResult contains the results of the benchmark operation
type BenchmarkResult struct {
	Samples         []BenchmarkSample
	TotalOps        uint64
	TotalTime       time.Duration
	AvgOpsPerSecond float64
	TimeEstimates   []TimeEstimate
}

// TimeEstimate represents an estimated time for a given work factor
type TimeEstimate struct {
	WorkFactor    uint64
	EstimatedTime time.Duration
}

// RunBenchmark performs the core benchmarking logic
func RunBenchmark(opts BenchmarkOptions) (*BenchmarkResult, error) {
	// Generate a test puzzle to get realistic RSA modulus (no password for benchmark)
	testPuzzle, _, err := crypto.GeneratePuzzle(1, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to generate test puzzle: %v", err)
	}

	var samples []BenchmarkSample
	var totalOps uint64
	var totalTime time.Duration

	for sample := 1; sample <= opts.Samples; sample++ {
		ops, elapsed := benchmarkSquaring(testPuzzle.N, opts.Duration)
		opsPerSecond := float64(ops) / elapsed.Seconds()

		sampleResult := BenchmarkSample{
			Operations:   ops,
			Elapsed:      elapsed,
			OpsPerSecond: opsPerSecond,
		}

		samples = append(samples, sampleResult)
		totalOps += ops
		totalTime += elapsed
	}

	// Calculate average performance
	avgOpsPerSecond := float64(totalOps) / totalTime.Seconds()

	// Generate time estimates for common work factors
	workFactors := []uint64{
		1000000,     // ~1 second
		60000000,    // ~1 minute
		3600000000,  // ~1 hour
		86400000000, // ~1 day
	}

	var timeEstimates []TimeEstimate
	for _, wf := range workFactors {
		estimatedTime := utils.EstimateTime(wf, avgOpsPerSecond)
		timeEstimates = append(timeEstimates, TimeEstimate{
			WorkFactor:    wf,
			EstimatedTime: estimatedTime,
		})
	}

	return &BenchmarkResult{
		Samples:         samples,
		TotalOps:        totalOps,
		TotalTime:       totalTime,
		AvgOpsPerSecond: avgOpsPerSecond,
		TimeEstimates:   timeEstimates,
	}, nil
}

// benchmarkSquaring performs modular squaring operations for the specified duration
// and returns the number of operations performed and actual elapsed time
func benchmarkSquaring(N *big.Int, duration time.Duration) (uint64, time.Duration) {
	// Start with a random value
	x := big.NewInt(12345)
	x.Mod(x, N)

	var operations uint64
	start := time.Now()
	end := start.Add(duration)

	for time.Now().Before(end) {
		// Perform a batch of squaring operations to reduce time.Now() overhead
		for i := 0; i < 1000; i++ {
			x = crypto.SequentialSquaring(x, N)
			operations++
		}
	}

	elapsed := time.Since(start)
	return operations, elapsed
}
