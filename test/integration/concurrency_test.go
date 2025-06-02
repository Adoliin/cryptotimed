package integration

import (
	"bytes"
	"fmt"
	"sync"
	"testing"

	"cryptotimed/src/operations"
	"cryptotimed/src/utils"
)

// Concurrent Access Tests

func TestConcurrentEncryption(t *testing.T) {
	const numGoroutines = 5
	testData := []byte("Concurrent encryption test data")

	var wg sync.WaitGroup
	errors := make(chan error, numGoroutines)

	for i := range numGoroutines {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()

			inputFile := createTempFile(t, fmt.Sprintf("concurrent_input_%d.txt", id), testData)

			encryptOpts := operations.EncryptOptions{
				InputFile:  inputFile,
				WorkFactor: testWorkFactor,
				KeyInput:   fmt.Sprintf("password_%d", id),
			}

			result, err := operations.EncryptFile(encryptOpts)
			if err != nil {
				errors <- fmt.Errorf("goroutine %d encryption failed: %v", id, err)
				return
			}

			// Verify we can decrypt
			decryptOpts := operations.DecryptOptions{
				InputFile: result.OutputFile,
				KeyInput:  fmt.Sprintf("password_%d", id),
			}

			_, err = operations.DecryptFile(decryptOpts, nil)
			if err != nil {
				errors <- fmt.Errorf("goroutine %d decryption failed: %v", id, err)
				return
			}
		}(i)
	}

	wg.Wait()
	close(errors)

	// Check for any errors
	for err := range errors {
		t.Error(err)
	}
}

func TestConcurrentDecryption(t *testing.T) {
	const numGoroutines = 3
	testData := []byte("Concurrent decryption test data")

	// Create a single encrypted file
	inputFile := createTempFile(t, "shared_input.txt", testData)
	encryptOpts := operations.EncryptOptions{
		InputFile:  inputFile,
		WorkFactor: testWorkFactor,
		KeyInput:   "",
	}

	encryptResult, err := operations.EncryptFile(encryptOpts)
	if err != nil {
		t.Fatalf("Failed to create encrypted file: %v", err)
	}

	// Decrypt concurrently
	var wg sync.WaitGroup
	errors := make(chan error, numGoroutines)

	for i := range numGoroutines {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()

			decryptOpts := operations.DecryptOptions{
				InputFile:  encryptResult.OutputFile,
				KeyInput:   "",
				OutputFile: fmt.Sprintf("%s.decrypted_%d", encryptResult.OutputFile, id),
			}

			result, err := operations.DecryptFile(decryptOpts, nil)
			if err != nil {
				errors <- fmt.Errorf("goroutine %d decryption failed: %v", id, err)
				return
			}

			// Verify decrypted content
			decryptedData, err := utils.ReadFile(result.OutputFile)
			if err != nil {
				errors <- fmt.Errorf("goroutine %d failed to read result: %v", id, err)
				return
			}

			if !bytes.Equal(testData, decryptedData) {
				errors <- fmt.Errorf("goroutine %d data mismatch", id)
				return
			}
		}(i)
	}

	wg.Wait()
	close(errors)

	// Check for any errors
	for err := range errors {
		t.Error(err)
	}
}
