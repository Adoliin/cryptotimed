package crypto

import (
	"bytes"
	"testing"
)

// Note: DeriveFinalKey, EncryptKey, and DecryptKey tests removed since those functions
// were removed. Password is now integrated directly into the puzzle.

func TestEncryptDecryptData(t *testing.T) {
	key := [32]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
		17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32}

	testData := []byte("Hello, World! This is test data for encryption.")

	// Encrypt
	ciphertext, err := EncryptData(key, testData)
	if err != nil {
		t.Fatalf("EncryptData failed: %v", err)
	}

	// Should be different from plaintext
	if bytes.Equal(ciphertext, testData) {
		t.Errorf("Ciphertext should be different from plaintext")
	}

	// Should be longer (includes nonce and auth tag)
	if len(ciphertext) <= len(testData) {
		t.Errorf("Ciphertext should be longer than plaintext")
	}

	// Decrypt
	decrypted, err := DecryptData(key, ciphertext)
	if err != nil {
		t.Fatalf("DecryptData failed: %v", err)
	}

	// Should match original
	if !bytes.Equal(decrypted, testData) {
		t.Errorf("Decrypted data doesn't match original")
	}
}

func TestDecryptDataWithWrongKey(t *testing.T) {
	key1 := [32]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
		17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32}
	key2 := [32]byte{32, 31, 30, 29, 28, 27, 26, 25, 24, 23, 22, 21, 20, 19, 18, 17,
		16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1}

	testData := []byte("Secret message")

	// Encrypt with key1
	ciphertext, err := EncryptData(key1, testData)
	if err != nil {
		t.Fatalf("EncryptData failed: %v", err)
	}

	// Try to decrypt with key2 (should fail)
	_, err = DecryptData(key2, ciphertext)
	if err == nil {
		t.Errorf("DecryptData should fail with wrong key")
	}
}
