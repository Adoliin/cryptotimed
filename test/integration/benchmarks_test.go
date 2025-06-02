package integration

import (
	"fmt"
	"testing"
	"time"

	"cryptotimed/src/operations"
)

// Benchmark Tests (for performance measurement)

func BenchmarkEncryption(b *testing.B) {
	testData := generateRandomData(1024) // 1KB test data

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		inputFile := createTempFileForBench(b, fmt.Sprintf("bench_input_%d.txt", i), testData)
		b.StartTimer()

		encryptOpts := operations.EncryptOptions{
			InputFile:  inputFile,
			WorkFactor: 1000, // Small work factor for benchmarking
			KeyInput:   "",
		}

		_, err := operations.EncryptFile(encryptOpts)
		if err != nil {
			b.Fatalf("Encryption failed: %v", err)
		}
	}
}

func BenchmarkDecryption(b *testing.B) {
	testData := generateRandomData(1024) // 1KB test data

	// Pre-create encrypted files
	encryptedFiles := make([]string, b.N)
	for i := 0; i < b.N; i++ {
		inputFile := createTempFileForBench(b, fmt.Sprintf("bench_input_%d.txt", i), testData)
		encryptOpts := operations.EncryptOptions{
			InputFile:  inputFile,
			WorkFactor: 1000, // Small work factor for benchmarking
			KeyInput:   "",
		}

		encryptResult, err := operations.EncryptFile(encryptOpts)
		if err != nil {
			b.Fatalf("Pre-encryption failed: %v", err)
		}
		encryptedFiles[i] = encryptResult.OutputFile
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		decryptOpts := operations.DecryptOptions{
			InputFile: encryptedFiles[i],
			KeyInput:  "",
		}

		_, err := operations.DecryptFile(decryptOpts, nil)
		if err != nil {
			b.Fatalf("Decryption failed: %v", err)
		}
	}
}

func BenchmarkBenchmarkOperation(b *testing.B) {
	opts := operations.BenchmarkOptions{
		Duration: 10 * time.Millisecond, // Very short for benchmarking
		Samples:  1,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := operations.RunBenchmark(opts)
		if err != nil {
			b.Fatalf("Benchmark operation failed: %v", err)
		}
	}
}
