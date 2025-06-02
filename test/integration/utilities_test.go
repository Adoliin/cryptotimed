package integration

import (
	"testing"

	"cryptotimed/src/crypto"
	"cryptotimed/src/types"
	"cryptotimed/src/utils"
)

// Utility function tests

func TestUtilityFunctions(t *testing.T) {
	t.Run("parse_key_input", func(t *testing.T) {
		// Test direct string input
		key1, err := utils.ParseKeyInput("direct_password")
		if err != nil {
			t.Fatalf("Failed to parse direct password: %v", err)
		}
		expected1 := []byte("direct_password")
		assertBytesEqual(t, expected1, key1, "Direct password parsing")

		// Test empty input
		key2, err := utils.ParseKeyInput("")
		if err != nil {
			t.Fatalf("Failed to parse empty input: %v", err)
		}
		if key2 != nil {
			t.Error("Empty input should return nil")
		}

		// Test file input
		keyContent := "file_based_password"
		keyFile := createTempKeyFile(t, keyContent)
		key3, err := utils.ParseKeyInput("@file:" + keyFile)
		if err != nil {
			t.Fatalf("Failed to parse file input: %v", err)
		}
		expected3 := []byte(keyContent)
		assertBytesEqual(t, expected3, key3, "File-based password parsing")

		// Test invalid file input
		_, err = utils.ParseKeyInput("@file:/nonexistent/file.txt")
		if err == nil {
			t.Error("Expected error for nonexistent file")
		}
	})

	t.Run("puzzle_conversion", func(t *testing.T) {
		// Generate a test puzzle
		puzzle, _, err := crypto.GeneratePuzzle(testWorkFactor, []byte("test_password"))
		if err != nil {
			t.Fatalf("Failed to generate test puzzle: %v", err)
		}

		// Convert to bytes and back
		nBytes, gBytes := utils.PuzzleToBytes(puzzle)

		// Create encrypted file structure
		ef := &types.EncryptedFile{
			Version:     types.CurrentVersion,
			WorkFactor:  puzzle.T,
			ModulusN:    nBytes,
			BaseG:       gBytes,
			KeyRequired: 1,
			Salt:        puzzle.Salt,
			Data:        []byte("test_data"),
		}

		// Convert back to puzzle
		reconstructed := utils.PuzzleFromEncryptedFile(ef)

		// Verify reconstruction
		if reconstructed.N.Cmp(puzzle.N) != 0 {
			t.Error("Reconstructed N does not match original")
		}
		if reconstructed.G.Cmp(puzzle.G) != 0 {
			t.Error("Reconstructed G does not match original")
		}
		if reconstructed.T != puzzle.T {
			t.Error("Reconstructed T does not match original")
		}
		if reconstructed.Salt != puzzle.Salt {
			t.Error("Reconstructed Salt does not match original")
		}
	})
}
