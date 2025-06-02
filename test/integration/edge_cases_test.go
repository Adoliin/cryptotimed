package integration

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"cryptotimed/src/operations"
	"cryptotimed/src/utils"
)

// Edge Cases and Boundary Tests

func TestLargeFileHandling(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping large file test in short mode")
	}

	// Create a large file (1MB)
	largeData := generateRandomData(1024 * 1024)
	inputFile := createTempFile(t, "large_input.bin", largeData)

	encryptOpts := operations.EncryptOptions{
		InputFile:  inputFile,
		WorkFactor: testWorkFactor,
		KeyInput:   "large_file_password",
	}

	encryptResult, err := operations.EncryptFile(encryptOpts)
	if err != nil {
		t.Fatalf("Large file encryption failed: %v", err)
	}

	// Verify encryption worked
	if encryptResult.PlaintextSize != len(largeData) {
		t.Errorf("Expected plaintext size %d, got %d", len(largeData), encryptResult.PlaintextSize)
	}

	decryptOpts := operations.DecryptOptions{
		InputFile: encryptResult.OutputFile,
		KeyInput:  "large_file_password",
	}

	decryptResult, err := operations.DecryptFile(decryptOpts, nil)
	if err != nil {
		t.Fatalf("Large file decryption failed: %v", err)
	}

	// Verify decrypted content matches original
	decryptedData, err := utils.ReadFile(decryptResult.OutputFile)
	if err != nil {
		t.Fatalf("Failed to read large decrypted file: %v", err)
	}

	assertBytesEqual(t, largeData, decryptedData, "Large file decryption")
}

func TestExtremeWorkFactors(t *testing.T) {
	testData := []byte("Test data for extreme work factors")
	inputFile := createTempFile(t, "input.txt", testData)

	extremeTests := []struct {
		name       string
		workFactor uint64
		shouldWork bool
	}{
		{"zero_work", 0, true},
		{"one_work", 1, true},
		{"small_work", 10, true},
		{"large_work", 1000000, true}, // Only test if not in short mode
	}

	for _, test := range extremeTests {
		t.Run(test.name, func(t *testing.T) {
			if test.workFactor > 100000 && testing.Short() {
				t.Skip("Skipping large work factor test in short mode")
			}

			encryptOpts := operations.EncryptOptions{
				InputFile:  inputFile,
				WorkFactor: test.workFactor,
				KeyInput:   "",
			}

			encryptResult, err := operations.EncryptFile(encryptOpts)
			if !test.shouldWork {
				if err == nil {
					t.Fatalf("Expected error for work factor %d", test.workFactor)
				}
				return
			}

			if err != nil {
				t.Fatalf("Unexpected error for work factor %d: %v", test.workFactor, err)
			}

			if encryptResult.WorkFactor != test.workFactor {
				t.Errorf("Expected work factor %d, got %d", test.workFactor, encryptResult.WorkFactor)
			}

			// Test decryption
			decryptOpts := operations.DecryptOptions{
				InputFile: encryptResult.OutputFile,
				KeyInput:  "",
			}

			decryptResult, err := operations.DecryptFile(decryptOpts, nil)
			if err != nil {
				t.Fatalf("Decryption failed for work factor %d: %v", test.workFactor, err)
			}

			// Verify content
			decryptedData, err := utils.ReadFile(decryptResult.OutputFile)
			if err != nil {
				t.Fatalf("Failed to read decrypted file: %v", err)
			}

			assertBytesEqual(t, testData, decryptedData, fmt.Sprintf("Work factor %d", test.workFactor))
		})
	}
}

func TestSpecialCharactersInPasswords(t *testing.T) {
	testData := []byte("Data with special character passwords")
	inputFile := createTempFile(t, "input.txt", testData)

	specialPasswords := []string{
		"password with spaces",
		"password\nwith\nnewlines",
		"password\twith\ttabs",
		"password\"with'quotes",
		"password\\with\\backslashes",
		"password/with/slashes",
		"password|with|pipes",
		"password<with>brackets",
		"password{with}braces",
		"password[with]squares",
		"password(with)parens",
		"password@with#symbols$%^&*()",
		"密码with中文",
		"пароль_кириллица",
		"🔐🗝️🔑", // Emoji password
	}

	for i, password := range specialPasswords {
		t.Run(fmt.Sprintf("special_password_%d", i), func(t *testing.T) {
			encryptOpts := operations.EncryptOptions{
				InputFile:  inputFile,
				WorkFactor: testWorkFactor,
				KeyInput:   password,
			}

			encryptResult, err := operations.EncryptFile(encryptOpts)
			if err != nil {
				t.Fatalf("Encryption failed with special password: %v", err)
			}

			decryptOpts := operations.DecryptOptions{
				InputFile: encryptResult.OutputFile,
				KeyInput:  password,
			}

			decryptResult, err := operations.DecryptFile(decryptOpts, nil)
			if err != nil {
				t.Fatalf("Decryption failed with special password: %v", err)
			}

			// Verify content
			decryptedData, err := utils.ReadFile(decryptResult.OutputFile)
			if err != nil {
				t.Fatalf("Failed to read decrypted file: %v", err)
			}

			assertBytesEqual(t, testData, decryptedData, "Special character password")
		})
	}
}

func TestOutputFileNaming(t *testing.T) {
	testData := []byte("Test output file naming")

	tests := []struct {
		name           string
		inputFileName  string
		expectedOutput string
	}{
		{"simple_txt", "document.txt", "document.txt.locked"},
		{"no_extension", "document", "document.locked"},
		{"multiple_dots", "my.file.name.txt", "my.file.name.txt.locked"},
		{"hidden_file", ".hidden", ".hidden.locked"},
		{"path_with_dirs", "subdir/file.txt", "subdir/file.txt.locked"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Create directory structure if needed
			inputFile := createTempFile(t, test.inputFileName, testData)

			encryptOpts := operations.EncryptOptions{
				InputFile:  inputFile,
				WorkFactor: testWorkFactor,
				KeyInput:   "",
			}

			encryptResult, err := operations.EncryptFile(encryptOpts)
			if err != nil {
				t.Fatalf("Encryption failed: %v", err)
			}

			expectedPath := inputFile + ".locked"
			if encryptResult.OutputFile != expectedPath {
				t.Errorf("Expected output file %s, got %s", expectedPath, encryptResult.OutputFile)
			}

			assertFileExists(t, encryptResult.OutputFile)
		})
	}
}

func TestDecryptOutputFileNaming(t *testing.T) {
	testData := []byte("Test decrypt output file naming")

	tests := []struct {
		name              string
		encryptedFileName string
		customOutput      string
		expectedOutput    string
	}{
		{"auto_locked_suffix", "document.txt.locked", "", "document.txt"},
		{"auto_no_locked_suffix", "document.encrypted", "", "document.encrypted.decrypted"},
		{"custom_output", "document.txt.locked", "custom_output.txt", "custom_output.txt"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// First encrypt a file
			inputFile := createTempFile(t, "original.txt", testData)
			encryptOpts := operations.EncryptOptions{
				InputFile:  inputFile,
				WorkFactor: testWorkFactor,
				KeyInput:   "",
			}

			encryptResult, err := operations.EncryptFile(encryptOpts)
			if err != nil {
				t.Fatalf("Encryption failed: %v", err)
			}

			// Rename encrypted file to test name
			tmpDir := filepath.Dir(encryptResult.OutputFile)
			testEncryptedFile := filepath.Join(tmpDir, test.encryptedFileName)
			if err := os.Rename(encryptResult.OutputFile, testEncryptedFile); err != nil {
				t.Fatalf("Failed to rename encrypted file: %v", err)
			}

			// Decrypt with custom output if specified
			decryptOpts := operations.DecryptOptions{
				InputFile:  testEncryptedFile,
				KeyInput:   "",
				OutputFile: test.customOutput,
			}

			if test.customOutput != "" {
				decryptOpts.OutputFile = filepath.Join(tmpDir, test.customOutput)
			}

			decryptResult, err := operations.DecryptFile(decryptOpts, nil)
			if err != nil {
				t.Fatalf("Decryption failed: %v", err)
			}

			// Check expected output file name
			var expectedPath string
			if test.customOutput != "" {
				expectedPath = filepath.Join(tmpDir, test.customOutput)
			} else if test.expectedOutput == "document.txt" {
				expectedPath = filepath.Join(tmpDir, "document.txt")
			} else {
				expectedPath = filepath.Join(tmpDir, test.expectedOutput)
			}

			if decryptResult.OutputFile != expectedPath {
				t.Errorf("Expected output file %s, got %s", expectedPath, decryptResult.OutputFile)
			}

			assertFileExists(t, decryptResult.OutputFile)
		})
	}
}
