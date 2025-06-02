package integration

import (
	"fmt"
	"testing"

	"cryptotimed/src/operations"
	"cryptotimed/src/utils"
)

// Stress Tests

func TestStressEncryptionDecryption(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping stress test in short mode")
	}

	const numIterations = 20
	testData := []byte("Stress test data for multiple encrypt/decrypt cycles")

	for i := range numIterations {
		t.Run(fmt.Sprintf("iteration_%d", i), func(t *testing.T) {
			inputFile := createTempFile(t, fmt.Sprintf("stress_input_%d.txt", i), testData)

			encryptOpts := operations.EncryptOptions{
				InputFile:  inputFile,
				WorkFactor: testWorkFactor,
				KeyInput:   fmt.Sprintf("stress_password_%d", i),
			}

			encryptResult, err := operations.EncryptFile(encryptOpts)
			if err != nil {
				t.Fatalf("Iteration %d encryption failed: %v", i, err)
			}

			decryptOpts := operations.DecryptOptions{
				InputFile: encryptResult.OutputFile,
				KeyInput:  fmt.Sprintf("stress_password_%d", i),
			}

			decryptResult, err := operations.DecryptFile(decryptOpts, nil)
			if err != nil {
				t.Fatalf("Iteration %d decryption failed: %v", i, err)
			}

			// Verify content
			decryptedData, err := utils.ReadFile(decryptResult.OutputFile)
			if err != nil {
				t.Fatalf("Iteration %d failed to read result: %v", i, err)
			}

			assertBytesEqual(t, testData, decryptedData, fmt.Sprintf("Iteration %d", i))
		})
	}
}
