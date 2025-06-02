package integration

import (
	"strings"
	"testing"

	"cryptotimed/src/operations"
)

// Error Handling Tests

func TestEncryptionErrorHandling(t *testing.T) {
	t.Run("nonexistent_input_file", func(t *testing.T) {
		opts := operations.EncryptOptions{
			InputFile:  "/nonexistent/file.txt",
			WorkFactor: testWorkFactor,
			KeyInput:   "",
		}

		_, err := operations.EncryptFile(opts)
		if err == nil {
			t.Fatal("Expected error for nonexistent input file")
		}
		if !strings.Contains(err.Error(), "failed to read input file") {
			t.Errorf("Expected 'failed to read input file' error, got: %v", err)
		}
	})

	t.Run("invalid_key_file", func(t *testing.T) {
		inputFile := createTempFile(t, "input.txt", []byte("test"))

		opts := operations.EncryptOptions{
			InputFile:  inputFile,
			WorkFactor: testWorkFactor,
			KeyInput:   "@file:/nonexistent/keyfile.txt",
		}

		_, err := operations.EncryptFile(opts)
		if err == nil {
			t.Fatal("Expected error for nonexistent key file")
		}
		if !strings.Contains(err.Error(), "failed to parse key input") {
			t.Errorf("Expected 'failed to parse key input' error, got: %v", err)
		}
	})

	t.Run("zero_work_factor", func(t *testing.T) {
		inputFile := createTempFile(t, "input.txt", []byte("test"))

		opts := operations.EncryptOptions{
			InputFile:  inputFile,
			WorkFactor: 0,
			KeyInput:   "",
		}

		// Zero work factor should be allowed (instant decryption)
		result, err := operations.EncryptFile(opts)
		if err != nil {
			t.Fatalf("Unexpected error for zero work factor: %v", err)
		}
		if result.WorkFactor != 0 {
			t.Errorf("Expected work factor 0, got %d", result.WorkFactor)
		}
	})
}

func TestDecryptionErrorHandling(t *testing.T) {
	t.Run("nonexistent_encrypted_file", func(t *testing.T) {
		opts := operations.DecryptOptions{
			InputFile: "/nonexistent/file.locked",
			KeyInput:  "",
		}

		_, err := operations.DecryptFile(opts, nil)
		if err == nil {
			t.Fatal("Expected error for nonexistent encrypted file")
		}
		if !strings.Contains(err.Error(), "failed to read encrypted file") {
			t.Errorf("Expected 'failed to read encrypted file' error, got: %v", err)
		}
	})

	t.Run("wrong_password", func(t *testing.T) {
		testData := []byte("Secret data")
		inputFile := createTempFile(t, "input.txt", testData)

		// Encrypt with password
		encryptOpts := operations.EncryptOptions{
			InputFile:  inputFile,
			WorkFactor: testWorkFactor,
			KeyInput:   "correct_password",
		}

		encryptResult, err := operations.EncryptFile(encryptOpts)
		if err != nil {
			t.Fatalf("Encryption failed: %v", err)
		}

		// Try to decrypt with wrong password
		decryptOpts := operations.DecryptOptions{
			InputFile: encryptResult.OutputFile,
			KeyInput:  "wrong_password",
		}

		_, err = operations.DecryptFile(decryptOpts, nil)
		if err == nil {
			t.Fatal("Expected error for wrong password")
		}
		if !strings.Contains(err.Error(), "failed to decrypt data") {
			t.Errorf("Expected 'failed to decrypt data' error, got: %v", err)
		}
	})

	t.Run("missing_required_password", func(t *testing.T) {
		testData := []byte("Secret data")
		inputFile := createTempFile(t, "input.txt", testData)

		// Encrypt with password
		encryptOpts := operations.EncryptOptions{
			InputFile:  inputFile,
			WorkFactor: testWorkFactor,
			KeyInput:   "required_password",
		}

		encryptResult, err := operations.EncryptFile(encryptOpts)
		if err != nil {
			t.Fatalf("Encryption failed: %v", err)
		}

		// Try to decrypt without password
		decryptOpts := operations.DecryptOptions{
			InputFile: encryptResult.OutputFile,
			KeyInput:  "",
		}

		_, err = operations.DecryptFile(decryptOpts, nil)
		if err == nil {
			t.Fatal("Expected error for missing required password")
		}
		if !strings.Contains(err.Error(), "requires a key to decrypt") {
			t.Errorf("Expected 'requires a key to decrypt' error, got: %v", err)
		}
	})

	t.Run("corrupted_file", func(t *testing.T) {
		// Create a corrupted encrypted file
		corruptedFile := createTempFile(t, "corrupted.locked", []byte("not a valid encrypted file"))

		opts := operations.DecryptOptions{
			InputFile: corruptedFile,
			KeyInput:  "",
		}

		_, err := operations.DecryptFile(opts, nil)
		if err == nil {
			t.Fatal("Expected error for corrupted file")
		}
	})
}
