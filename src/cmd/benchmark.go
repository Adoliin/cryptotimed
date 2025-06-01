package cmd

import (
	"flag"
	"fmt"
	"math/big"
	"os"
	"time"

	"cryptotimed/src/crypto"
	"cryptotimed/src/utils"
)

// BenchmarkCommand handles the benchmark subcommand
func BenchmarkCommand(args []string) error {
	fs := flag.NewFlagSet("benchmark", flag.ExitOnError)

	var (
		duration = fs.Duration("duration", 10*time.Second, "How long to run the benchmark")
		samples  = fs.Int("samples", 3, "Number of benchmark samples to take")
	)

	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s benchmark [--duration DURATION] [--samples COUNT]\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "\nBenchmark modular squaring performance to estimate work factors\n\n")
		fmt.Fprintf(os.Stderr, "Options:\n")
		fs.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nExamples:\n")
		fmt.Fprintf(os.Stderr, "  %s benchmark\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s benchmark --duration 30s --samples 5\n", os.Args[0])
	}

	if err := fs.Parse(args); err != nil {
		return err
	}

	fmt.Printf("Benchmarking modular squaring performance...\n")
	fmt.Printf("Duration per sample: %v\n", *duration)
	fmt.Printf("Number of samples: %d\n\n", *samples)

	// Generate a test puzzle to get realistic RSA modulus
	testPuzzle, _, err := crypto.GeneratePuzzle(1)
	if err != nil {
		return fmt.Errorf("failed to generate test puzzle: %v", err)
	}

	var totalOps uint64
	var totalTime time.Duration

	for sample := 1; sample <= *samples; sample++ {
		fmt.Printf("Running sample %d/%d...\n", sample, *samples)

		ops, elapsed := benchmarkSquaring(testPuzzle.N, *duration)
		opsPerSecond := float64(ops) / elapsed.Seconds()

		fmt.Printf("  Operations: %d\n", ops)
		fmt.Printf("  Time: %v\n", elapsed)
		fmt.Printf("  Rate: %.0f ops/sec\n\n", opsPerSecond)

		totalOps += ops
		totalTime += elapsed
	}

	// Calculate average performance
	avgOpsPerSecond := float64(totalOps) / totalTime.Seconds()

	fmt.Printf("=== Benchmark Results ===\n")
	fmt.Printf("Average rate: %.0f squarings/second\n", avgOpsPerSecond)
	fmt.Printf("Total operations: %d\n", totalOps)
	fmt.Printf("Total time: %v\n\n", totalTime)

	// Provide time estimates for common work factors
	fmt.Printf("=== Time Estimates ===\n")
	workFactors := []uint64{
		1000000,     // ~1 second
		60000000,    // ~1 minute
		3600000000,  // ~1 hour
		86400000000, // ~1 day
	}

	for _, wf := range workFactors {
		estimatedTime := utils.EstimateTime(wf, avgOpsPerSecond)
		fmt.Printf("Work factor %d: %s\n", wf, utils.FormatDuration(estimatedTime))
	}

	fmt.Printf("\nTo encrypt with a specific delay, use:\n")
	fmt.Printf("  cryptotimed encrypt --input file.txt --work ITERATIONS\n")
	fmt.Printf("\nWhere ITERATIONS = desired_seconds × %.0f\n", avgOpsPerSecond)

	return nil
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
