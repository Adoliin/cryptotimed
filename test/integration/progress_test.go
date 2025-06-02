package integration

import (
	"sync"
	"testing"

	"cryptotimed/src/operations"
)

// Progress Tracking Tests

func TestProgressCallbackAccuracy(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping progress test in short mode")
	}

	workFactor := uint64(50000) // Moderate work factor for progress testing
	testData := []byte("Progress tracking test data")
	inputFile := createTempFile(t, "progress_input.txt", testData)

	// Encrypt
	encryptOpts := operations.EncryptOptions{
		InputFile:  inputFile,
		WorkFactor: workFactor,
		KeyInput:   "",
	}

	encryptResult, err := operations.EncryptFile(encryptOpts)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	// Decrypt with progress tracking
	var progressUpdates []uint64
	var progressMutex sync.Mutex

	progressCallback := func(done uint64) {
		progressMutex.Lock()
		progressUpdates = append(progressUpdates, done)
		progressMutex.Unlock()
	}

	decryptOpts := operations.DecryptOptions{
		InputFile: encryptResult.OutputFile,
		KeyInput:  "",
	}

	_, err = operations.DecryptFile(decryptOpts, progressCallback)
	if err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}

	// Validate progress updates
	progressMutex.Lock()
	defer progressMutex.Unlock()

	if len(progressUpdates) == 0 {
		t.Fatal("No progress updates received")
	}

	// Progress should be monotonically increasing
	for i := 1; i < len(progressUpdates); i++ {
		if progressUpdates[i] <= progressUpdates[i-1] {
			t.Errorf("Progress not monotonic: %d -> %d", progressUpdates[i-1], progressUpdates[i])
		}
	}

	// Final progress should equal work factor
	finalProgress := progressUpdates[len(progressUpdates)-1]
	if finalProgress != workFactor {
		t.Errorf("Final progress %d does not match work factor %d", finalProgress, workFactor)
	}

	// Progress should start from a reasonable point (not 0 unless work factor is very small)
	if workFactor > 1000 && progressUpdates[0] == 0 {
		t.Error("First progress update should not be 0 for large work factors")
	}
}
