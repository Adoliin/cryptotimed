package integration

import (
	"testing"

	"cryptotimed/src/operations"
	"cryptotimed/src/types"
	"cryptotimed/src/utils"
)

// Regression Tests

func TestRegressionFileFormatCompatibility(t *testing.T) {
	// Test that we can handle different file format versions
	// This test ensures backward compatibility

	testData := []byte("Regression test data")
	inputFile := createTempFile(t, "regression_input.txt", testData)

	// Create current format file
	encryptOpts := operations.EncryptOptions{
		InputFile:  inputFile,
		WorkFactor: testWorkFactor,
		KeyInput:   "regression_password",
	}

	encryptResult, err := operations.EncryptFile(encryptOpts)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	// Read and verify file format
	ef, err := utils.ReadEncryptedFile(encryptResult.OutputFile)
	if err != nil {
		t.Fatalf("Failed to read encrypted file: %v", err)
	}

	if ef.Version != types.CurrentVersion {
		t.Errorf("Expected current version %d, got %d", types.CurrentVersion, ef.Version)
	}

	// Verify we can decrypt
	decryptOpts := operations.DecryptOptions{
		InputFile: encryptResult.OutputFile,
		KeyInput:  "regression_password",
	}

	decryptResult, err := operations.DecryptFile(decryptOpts, nil)
	if err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}

	// Verify content
	decryptedData, err := utils.ReadFile(decryptResult.OutputFile)
	if err != nil {
		t.Fatalf("Failed to read decrypted file: %v", err)
	}

	assertBytesEqual(t, testData, decryptedData, "Regression test")
}
