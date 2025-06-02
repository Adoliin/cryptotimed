package integration

import (
	"fmt"
	"strings"
	"testing"

	"cryptotimed/src/operations"
	"cryptotimed/src/utils"
)

// Core Encryption/Decryption Workflow Tests

func TestBasicEncryptDecryptWorkflow(t *testing.T) {
	fixtures := createTestFixtures()

	for _, fixture := range fixtures {
		t.Run(fixture.Name, func(t *testing.T) {
			// Create input file
			inputFile := createTempFile(t, "input.txt", fixture.Data)

			// Test encryption
			encryptOpts := operations.EncryptOptions{
				InputFile:  inputFile,
				WorkFactor: testWorkFactor,
				KeyInput:   "",
			}

			encryptResult, err := operations.EncryptFile(encryptOpts)
			if err != nil {
				t.Fatalf("Encryption failed: %v", err)
			}

			// Verify encryption result
			if encryptResult.InputFile != inputFile {
				t.Errorf("Expected input file %s, got %s", inputFile, encryptResult.InputFile)
			}
			if encryptResult.PlaintextSize != len(fixture.Data) {
				t.Errorf("Expected plaintext size %d, got %d", len(fixture.Data), encryptResult.PlaintextSize)
			}
			if encryptResult.WorkFactor != testWorkFactor {
				t.Errorf("Expected work factor %d, got %d", testWorkFactor, encryptResult.WorkFactor)
			}
			if encryptResult.KeyRequired {
				t.Error("Expected KeyRequired to be false for puzzle-only encryption")
			}

			// Verify encrypted file exists
			assertFileExists(t, encryptResult.OutputFile)

			// Test decryption
			decryptOpts := operations.DecryptOptions{
				InputFile: encryptResult.OutputFile,
				KeyInput:  "",
			}

			var progressCalls int
			progressCallback := func(done uint64) {
				progressCalls++
			}

			decryptResult, err := operations.DecryptFile(decryptOpts, progressCallback)
			if err != nil {
				t.Fatalf("Decryption failed: %v", err)
			}

			// Verify decryption result
			if decryptResult.PlaintextSize != len(fixture.Data) {
				t.Errorf("Expected decrypted size %d, got %d", len(fixture.Data), decryptResult.PlaintextSize)
			}
			if decryptResult.WorkFactor != testWorkFactor {
				t.Errorf("Expected work factor %d, got %d", testWorkFactor, decryptResult.WorkFactor)
			}

			// Verify progress callback was called
			if progressCalls == 0 {
				t.Error("Progress callback was never called")
			}

			// Verify decrypted file exists and matches original
			assertFileExists(t, decryptResult.OutputFile)

			decryptedData, err := utils.ReadFile(decryptResult.OutputFile)
			if err != nil {
				t.Fatalf("Failed to read decrypted file: %v", err)
			}

			assertBytesEqual(t, fixture.Data, decryptedData, "Decrypted data")
		})
	}
}

func TestPasswordProtectedEncryptDecrypt(t *testing.T) {
	testData := []byte("Secret message that requires a password")
	passwords := []string{
		"simple",
		"complex_password_123!@#",
		"unicode_password_世界🌍",
		"very_long_password_" + strings.Repeat("x", 100),
		"", // Empty password (should work like no password)
	}

	for _, password := range passwords {
		t.Run(fmt.Sprintf("password_%s", password), func(t *testing.T) {
			inputFile := createTempFile(t, "secret.txt", testData)

			// Encrypt with password
			encryptOpts := operations.EncryptOptions{
				InputFile:  inputFile,
				WorkFactor: testWorkFactor,
				KeyInput:   password,
			}

			encryptResult, err := operations.EncryptFile(encryptOpts)
			if err != nil {
				t.Fatalf("Encryption with password failed: %v", err)
			}

			expectedKeyRequired := len(password) > 0
			if encryptResult.KeyRequired != expectedKeyRequired {
				t.Errorf("Expected KeyRequired %v, got %v", expectedKeyRequired, encryptResult.KeyRequired)
			}

			// Decrypt with correct password
			decryptOpts := operations.DecryptOptions{
				InputFile: encryptResult.OutputFile,
				KeyInput:  password,
			}

			decryptResult, err := operations.DecryptFile(decryptOpts, nil)
			if err != nil {
				t.Fatalf("Decryption with correct password failed: %v", err)
			}

			// Verify decrypted content
			decryptedData, err := utils.ReadFile(decryptResult.OutputFile)
			if err != nil {
				t.Fatalf("Failed to read decrypted file: %v", err)
			}

			assertBytesEqual(t, testData, decryptedData, "Password-protected decryption")
		})
	}
}

func TestKeyFileSupport(t *testing.T) {
	testData := []byte("Data encrypted with key from file")
	keyContent := "file_based_key_123"

	inputFile := createTempFile(t, "input.txt", testData)
	keyFile := createTempKeyFile(t, keyContent)

	// Encrypt with key from file
	encryptOpts := operations.EncryptOptions{
		InputFile:  inputFile,
		WorkFactor: testWorkFactor,
		KeyInput:   "@file:" + keyFile,
	}

	encryptResult, err := operations.EncryptFile(encryptOpts)
	if err != nil {
		t.Fatalf("Encryption with key file failed: %v", err)
	}

	if !encryptResult.KeyRequired {
		t.Error("Expected KeyRequired to be true for key file encryption")
	}

	// Decrypt with key from file
	decryptOpts := operations.DecryptOptions{
		InputFile: encryptResult.OutputFile,
		KeyInput:  "@file:" + keyFile,
	}

	decryptResult, err := operations.DecryptFile(decryptOpts, nil)
	if err != nil {
		t.Fatalf("Decryption with key file failed: %v", err)
	}

	// Verify decrypted content
	decryptedData, err := utils.ReadFile(decryptResult.OutputFile)
	if err != nil {
		t.Fatalf("Failed to read decrypted file: %v", err)
	}

	assertBytesEqual(t, testData, decryptedData, "Key file decryption")
}
