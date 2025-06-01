package utils

import (
	"bytes"
	"math/big"
	"os"
	"path/filepath"
	"testing"

	"cryptotimed/src/crypto"
	"cryptotimed/src/types"
)

func TestWriteReadEncryptedFile(t *testing.T) {
	// Create a temporary directory for test files
	tempDir, err := os.MkdirTemp("", "cryptotimed_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Create test encrypted file
	ef := &types.EncryptedFile{
		Version:     types.CurrentVersion,
		WorkFactor:  12345,
		KeyRequired: 1,
		Data:        []byte("test encrypted data"),
	}

	// Fill in some test values for the arrays
	for i := 0; i < types.Rsa2048Bytes; i++ {
		ef.ModulusN[i] = byte(i % 256)
		ef.BaseG[i] = byte((i + 100) % 256)
	}
	for i := 0; i < 48; i++ {
		ef.EncKey[i] = byte((i + 50) % 256)
	}
	for i := 0; i < 12; i++ {
		ef.Nonce[i] = byte((i + 200) % 256)
	}

	// Write to file
	testFile := filepath.Join(tempDir, "test.locked")
	err = WriteEncryptedFile(testFile, ef)
	if err != nil {
		t.Fatalf("WriteEncryptedFile failed: %v", err)
	}

	// Read back from file
	ef2, err := ReadEncryptedFile(testFile)
	if err != nil {
		t.Fatalf("ReadEncryptedFile failed: %v", err)
	}

	// Compare all fields
	if ef2.Version != ef.Version {
		t.Errorf("Version mismatch: got %d, want %d", ef2.Version, ef.Version)
	}
	if ef2.WorkFactor != ef.WorkFactor {
		t.Errorf("WorkFactor mismatch: got %d, want %d", ef2.WorkFactor, ef.WorkFactor)
	}
	if ef2.KeyRequired != ef.KeyRequired {
		t.Errorf("KeyRequired mismatch: got %d, want %d", ef2.KeyRequired, ef.KeyRequired)
	}
	if ef2.ModulusN != ef.ModulusN {
		t.Errorf("ModulusN mismatch")
	}
	if ef2.BaseG != ef.BaseG {
		t.Errorf("BaseG mismatch")
	}
	if ef2.EncKey != ef.EncKey {
		t.Errorf("EncKey mismatch")
	}
	if ef2.Nonce != ef.Nonce {
		t.Errorf("Nonce mismatch")
	}
	if !bytes.Equal(ef2.Data, ef.Data) {
		t.Errorf("Data mismatch")
	}
}

func TestPuzzleFromEncryptedFile(t *testing.T) {
	// Generate a real puzzle for testing
	originalPuzzle, _, err := crypto.GeneratePuzzle(100)
	if err != nil {
		t.Fatalf("Failed to generate puzzle: %v", err)
	}

	// Convert to byte arrays
	nBytes, gBytes := PuzzleToBytes(originalPuzzle)

	// Create encrypted file with puzzle data
	ef := &types.EncryptedFile{
		WorkFactor: originalPuzzle.T,
		ModulusN:   nBytes,
		BaseG:      gBytes,
	}

	// Extract puzzle back
	extractedPuzzle := PuzzleFromEncryptedFile(ef)

	// Compare
	if extractedPuzzle.T != originalPuzzle.T {
		t.Errorf("T mismatch: got %d, want %d", extractedPuzzle.T, originalPuzzle.T)
	}
	if extractedPuzzle.N.Cmp(originalPuzzle.N) != 0 {
		t.Errorf("N mismatch")
	}
	if extractedPuzzle.G.Cmp(originalPuzzle.G) != 0 {
		t.Errorf("G mismatch")
	}
}

func TestPuzzleToBytes(t *testing.T) {
	// Create test puzzle
	puzzle := crypto.Puzzle{
		N: big.NewInt(12345),
		G: big.NewInt(67890),
		T: 100,
	}

	// Convert to bytes
	nBytes, gBytes := PuzzleToBytes(puzzle)

	// Convert back to big.Int
	nRecovered := new(big.Int).SetBytes(nBytes[:])
	gRecovered := new(big.Int).SetBytes(gBytes[:])

	// Should match (note: leading zeros are preserved in the byte arrays)
	if nRecovered.Cmp(puzzle.N) != 0 {
		t.Errorf("N conversion failed: got %s, want %s", nRecovered, puzzle.N)
	}
	if gRecovered.Cmp(puzzle.G) != 0 {
		t.Errorf("G conversion failed: got %s, want %s", gRecovered, puzzle.G)
	}
}

func TestParseKeyInput(t *testing.T) {
	// Test empty input
	result, err := ParseKeyInput("")
	if err != nil {
		t.Errorf("ParseKeyInput(\"\") failed: %v", err)
	}
	if result != nil {
		t.Errorf("Expected nil for empty input, got %v", result)
	}

	// Test direct string input
	testString := "test passphrase"
	result, err = ParseKeyInput(testString)
	if err != nil {
		t.Errorf("ParseKeyInput failed: %v", err)
	}
	if !bytes.Equal(result, []byte(testString)) {
		t.Errorf("String input mismatch: got %s, want %s", result, testString)
	}

	// Test file input
	tempDir, err := os.MkdirTemp("", "cryptotimed_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	testFile := filepath.Join(tempDir, "keyfile.txt")
	testContent := []byte("file content passphrase")
	err = os.WriteFile(testFile, testContent, 0644)
	if err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	result, err = ParseKeyInput("@file:" + testFile)
	if err != nil {
		t.Errorf("ParseKeyInput file failed: %v", err)
	}
	if !bytes.Equal(result, testContent) {
		t.Errorf("File input mismatch: got %s, want %s", result, testContent)
	}

	// Test non-existent file
	_, err = ParseKeyInput("@file:/nonexistent/file")
	if err == nil {
		t.Errorf("Expected error for non-existent file")
	}
}

func TestReadWriteFile(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "cryptotimed_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	testFile := filepath.Join(tempDir, "test.txt")
	testData := []byte("Hello, World!")

	// Write file
	err = WriteFile(testFile, testData)
	if err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	// Read file
	readData, err := ReadFile(testFile)
	if err != nil {
		t.Fatalf("ReadFile failed: %v", err)
	}

	// Compare
	if !bytes.Equal(readData, testData) {
		t.Errorf("File content mismatch: got %s, want %s", readData, testData)
	}
}
