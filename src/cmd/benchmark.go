package cmd

import (
	"flag"
	"fmt"
	"os"
	"time"

	"cryptotimed/src/operations"
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

	// Prepare options for the operation
	opts := operations.BenchmarkOptions{
		Duration: *duration,
		Samples:  *samples,
	}

	// Display initial progress messages
	fmt.Printf("Benchmarking modular squaring performance...\n")
	fmt.Printf("Duration per sample: %v\n", *duration)
	fmt.Printf("Number of samples: %d\n\n", *samples)

	// Perform the benchmark operation
	result, err := operations.RunBenchmark(opts)
	if err != nil {
		return err
	}

	// Display sample results
	for i, sample := range result.Samples {
		fmt.Printf("Running sample %d/%d...\n", i+1, *samples)
		fmt.Printf("  Operations: %d\n", sample.Operations)
		fmt.Printf("  Time: %v\n", sample.Elapsed)
		fmt.Printf("  Rate: %.0f ops/sec\n\n", sample.OpsPerSecond)
	}

	// Display overall results
	fmt.Printf("=== Benchmark Results ===\n")
	fmt.Printf("Average rate: %.0f squarings/second\n", result.AvgOpsPerSecond)
	fmt.Printf("Total operations: %d\n", result.TotalOps)
	fmt.Printf("Total time: %v\n\n", result.TotalTime)

	// Display time estimates
	fmt.Printf("=== Time Estimates ===\n")
	for _, estimate := range result.TimeEstimates {
		fmt.Printf("Work factor %d: %s\n", estimate.WorkFactor, utils.FormatDuration(estimate.EstimatedTime))
	}

	fmt.Printf("\nTo encrypt with a specific delay, use:\n")
	fmt.Printf("  cryptotimed encrypt --input file.txt --work ITERATIONS\n")
	fmt.Printf("\nWhere ITERATIONS = desired_seconds × %.0f\n", result.AvgOpsPerSecond)

	return nil
}
