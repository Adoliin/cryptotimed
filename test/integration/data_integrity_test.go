package integration

import (
	"math/big"
	"testing"

	"cryptotimed/src/operations"
	"cryptotimed/src/types"
	"cryptotimed/src/utils"
)

// Data Integrity and File Format Tests

func TestFileFormatIntegrity(t *testing.T) {
	testData := []byte("Test data for file format validation")
	inputFile := createTempFile(t, "input.txt", testData)

	// Encrypt file
	encryptOpts := operations.EncryptOptions{
		InputFile:  inputFile,
		WorkFactor: testWorkFactor,
		KeyInput:   "test_password",
	}

	encryptResult, err := operations.EncryptFile(encryptOpts)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	// Read and validate encrypted file structure
	ef, err := utils.ReadEncryptedFile(encryptResult.OutputFile)
	if err != nil {
		t.Fatalf("Failed to read encrypted file: %v", err)
	}

	// Validate file format fields
	if ef.Version != types.CurrentVersion {
		t.Errorf("Expected version %d, got %d", types.CurrentVersion, ef.Version)
	}
	if ef.WorkFactor != testWorkFactor {
		t.Errorf("Expected work factor %d, got %d", testWorkFactor, ef.WorkFactor)
	}
	if ef.KeyRequired != 1 {
		t.Errorf("Expected KeyRequired 1, got %d", ef.KeyRequired)
	}

	// Validate RSA modulus size
	N := new(big.Int).SetBytes(ef.ModulusN[:])
	if N.BitLen() != 2048 {
		t.Errorf("Expected 2048-bit modulus, got %d bits", N.BitLen())
	}

	// Validate base G
	G := new(big.Int).SetBytes(ef.BaseG[:])
	if G.Sign() <= 0 {
		t.Error("Base G should be positive")
	}

	// Validate salt is non-zero (for password-protected files)
	allZero := true
	for _, b := range ef.Salt {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Error("Salt should not be all zeros for password-protected files")
	}

	// Validate encrypted data is present
	if len(ef.Data) == 0 {
		t.Error("Encrypted data should not be empty")
	}
}

func TestDataIntegrityWithTampering(t *testing.T) {
	testData := []byte("Sensitive data that should detect tampering")
	inputFile := createTempFile(t, "input.txt", testData)

	// Encrypt file
	encryptOpts := operations.EncryptOptions{
		InputFile:  inputFile,
		WorkFactor: testWorkFactor,
		KeyInput:   "",
	}

	encryptResult, err := operations.EncryptFile(encryptOpts)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	// Read encrypted file
	encryptedData, err := utils.ReadFile(encryptResult.OutputFile)
	if err != nil {
		t.Fatalf("Failed to read encrypted file: %v", err)
	}

	// Tamper with different parts of the file
	tamperTests := []struct {
		name   string
		offset int
		value  byte
	}{
		{"work_factor", 4, 0xFF},
		{"modulus", 12, 0xFF},
		{"encrypted_data", len(encryptedData) - 10, 0xFF},
		{"auth_tag", len(encryptedData) - 5, 0xFF}, // Tamper with authentication tag
	}

	for _, test := range tamperTests {
		t.Run(test.name, func(t *testing.T) {
			// Create tampered copy
			tamperedData := make([]byte, len(encryptedData))
			copy(tamperedData, encryptedData)
			if test.offset < len(tamperedData) {
				tamperedData[test.offset] = test.value
			}

			tamperedFile := createTempFile(t, "tampered.locked", tamperedData)

			// Try to decrypt tampered file
			decryptOpts := operations.DecryptOptions{
				InputFile: tamperedFile,
				KeyInput:  "",
			}

			_, err := operations.DecryptFile(decryptOpts, nil)
			if err == nil {
				t.Error("Expected error when decrypting tampered file")
			}
		})
	}
}
