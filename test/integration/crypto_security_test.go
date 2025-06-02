package integration

import (
	"bytes"
	"testing"

	"cryptotimed/src/crypto"
)

// Cryptographic Security Tests

func TestKeyDerivationDeterminism(t *testing.T) {
	// Test that the same puzzle target always produces the same key
	puzzle, _, err := crypto.GeneratePuzzle(testWorkFactor, nil)
	if err != nil {
		t.Fatalf("Failed to generate puzzle: %v", err)
	}

	// Derive key multiple times
	key1 := crypto.DerivePuzzleKey(puzzle.Target)
	key2 := crypto.DerivePuzzleKey(puzzle.Target)
	key3 := crypto.DerivePuzzleKey(puzzle.Target)

	if key1 != key2 || key2 != key3 {
		t.Error("Key derivation is not deterministic")
	}

	// Test with different targets
	puzzle2, _, err := crypto.GeneratePuzzle(testWorkFactor, nil)
	if err != nil {
		t.Fatalf("Failed to generate second puzzle: %v", err)
	}

	key4 := crypto.DerivePuzzleKey(puzzle2.Target)
	if key1 == key4 {
		t.Error("Different puzzle targets should produce different keys")
	}
}

func TestPasswordBasedKeyDerivation(t *testing.T) {
	password := []byte("test_password")
	salt := [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}

	// Generate test RSA modulus
	puzzle, _, err := crypto.GeneratePuzzle(1, nil)
	if err != nil {
		t.Fatalf("Failed to generate test puzzle: %v", err)
	}

	// Derive base multiple times with same parameters
	base1, err := crypto.DeriveBaseFromPassword(password, salt, crypto.DefaultArgon2idParams, puzzle.N)
	if err != nil {
		t.Fatalf("Failed to derive base 1: %v", err)
	}

	base2, err := crypto.DeriveBaseFromPassword(password, salt, crypto.DefaultArgon2idParams, puzzle.N)
	if err != nil {
		t.Fatalf("Failed to derive base 2: %v", err)
	}

	if base1.Cmp(base2) != 0 {
		t.Error("Password-based key derivation is not deterministic")
	}

	// Test with different password
	differentPassword := []byte("different_password")
	base3, err := crypto.DeriveBaseFromPassword(differentPassword, salt, crypto.DefaultArgon2idParams, puzzle.N)
	if err != nil {
		t.Fatalf("Failed to derive base 3: %v", err)
	}

	if base1.Cmp(base3) == 0 {
		t.Error("Different passwords should produce different bases")
	}

	// Test with different salt
	differentSalt := [16]byte{16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1}
	base4, err := crypto.DeriveBaseFromPassword(password, differentSalt, crypto.DefaultArgon2idParams, puzzle.N)
	if err != nil {
		t.Fatalf("Failed to derive base 4: %v", err)
	}

	if base1.Cmp(base4) == 0 {
		t.Error("Different salts should produce different bases")
	}
}

func TestEncryptionAuthenticity(t *testing.T) {
	testData := []byte("Data to test encryption authenticity")

	// Test that encryption produces different ciphertext each time (due to random nonce)
	key := [32]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
		17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32}

	ciphertext1, err := crypto.EncryptData(key, testData)
	if err != nil {
		t.Fatalf("First encryption failed: %v", err)
	}

	ciphertext2, err := crypto.EncryptData(key, testData)
	if err != nil {
		t.Fatalf("Second encryption failed: %v", err)
	}

	// Ciphertexts should be different due to random nonce
	if bytes.Equal(ciphertext1, ciphertext2) {
		t.Error("Encryption should produce different ciphertext each time")
	}

	// But both should decrypt to the same plaintext
	plaintext1, err := crypto.DecryptData(key, ciphertext1)
	if err != nil {
		t.Fatalf("First decryption failed: %v", err)
	}

	plaintext2, err := crypto.DecryptData(key, ciphertext2)
	if err != nil {
		t.Fatalf("Second decryption failed: %v", err)
	}

	assertBytesEqual(t, testData, plaintext1, "First decryption")
	assertBytesEqual(t, testData, plaintext2, "Second decryption")
}
