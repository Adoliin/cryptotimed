package integration

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"cryptotimed/src/utils"
)

// Test configuration constants
const (
	testWorkFactor  = 1000             // Small work factor for fast tests
	largeWorkFactor = 100000           // Larger work factor for performance tests
	maxTestFileSize = 10 * 1024 * 1024 // 10MB max for large file tests
)

// TestFixture represents a test data fixture
type TestFixture struct {
	Name        string
	Data        []byte
	Description string
}

// createTestFixtures generates various test data patterns
func createTestFixtures() []TestFixture {
	return []TestFixture{
		{
			Name:        "empty",
			Data:        []byte{},
			Description: "Empty file",
		},
		{
			Name:        "small_text",
			Data:        []byte("Hello, World! This is a test message."),
			Description: "Small text content",
		},
		{
			Name:        "binary_data",
			Data:        []byte{0x00, 0x01, 0x02, 0xFF, 0xFE, 0xFD, 0xAA, 0x55},
			Description: "Binary data with various byte values",
		},
		{
			Name:        "unicode_text",
			Data:        []byte("Hello 世界! 🌍 Testing Unicode: αβγδε ñáéíóú"),
			Description: "Unicode text with various character sets",
		},
		{
			Name:        "large_text",
			Data:        bytes.Repeat([]byte("Lorem ipsum dolor sit amet, consectetur adipiscing elit. "), 1000),
			Description: "Large text file (~55KB)",
		},
		{
			Name:        "random_binary",
			Data:        generateRandomData(8192),
			Description: "Random binary data (8KB)",
		},
		{
			Name:        "all_zeros",
			Data:        make([]byte, 4096),
			Description: "File with all zero bytes",
		},
		{
			Name:        "all_ones",
			Data:        bytes.Repeat([]byte{0xFF}, 4096),
			Description: "File with all 0xFF bytes",
		},
	}
}

// generateRandomData creates random test data
func generateRandomData(size int) []byte {
	data := make([]byte, size)
	if _, err := rand.Read(data); err != nil {
		panic(fmt.Sprintf("Failed to generate random data: %v", err))
	}
	return data
}

// createTempFile creates a temporary file with given content
func createTempFile(t *testing.T, name string, content []byte) string {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, name)

	// Create directory if needed
	if dir := filepath.Dir(filePath); dir != tmpDir {
		if err := os.MkdirAll(dir, 0755); err != nil {
			t.Fatalf("Failed to create directory %s: %v", dir, err)
		}
	}

	if err := utils.WriteFile(filePath, content); err != nil {
		t.Fatalf("Failed to create temp file %s: %v", filePath, err)
	}
	return filePath
}

// createTempFileForBench creates a temporary file for benchmarks
func createTempFileForBench(b *testing.B, name string, content []byte) string {
	tmpDir := b.TempDir()
	filePath := filepath.Join(tmpDir, name)
	if err := utils.WriteFile(filePath, content); err != nil {
		b.Fatalf("Failed to create temp file %s: %v", filePath, err)
	}
	return filePath
}

// createTempKeyFile creates a temporary key file
func createTempKeyFile(t *testing.T, key string) string {
	return createTempFile(t, "keyfile.txt", []byte(key))
}

// assertFileExists checks if a file exists
func assertFileExists(t *testing.T, path string) {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		t.Fatalf("Expected file %s to exist, but it doesn't", path)
	}
}

// assertBytesEqual compares two byte slices
func assertBytesEqual(t *testing.T, expected, actual []byte, context string) {
	if !bytes.Equal(expected, actual) {
		t.Fatalf("%s: Expected %d bytes, got %d bytes. Data mismatch.",
			context, len(expected), len(actual))
	}
}

// Test Suite Setup and Teardown
func TestMain(m *testing.M) {
	// Global test setup
	code := m.Run()
	// Global test teardown
	os.Exit(code)
}
