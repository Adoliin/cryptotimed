package crypto

import (
	"bytes"
	"math/big"
	"testing"
)

func TestDeriveFinalKey(t *testing.T) {
	// Test puzzle target
	target := big.NewInt(12345)

	// Test case 1: No user key (puzzle-only)
	key1, keyRequired1 := DeriveFinalKey(target, nil)
	if keyRequired1 != 0 {
		t.Errorf("Expected keyRequired=0 for nil user key, got %d", keyRequired1)
	}

	// Should be same as DerivePuzzleKey
	expectedKey1 := DerivePuzzleKey(target)
	if key1 != expectedKey1 {
		t.Errorf("Key mismatch for puzzle-only case")
	}

	// Test case 2: Empty user key
	key2, keyRequired2 := DeriveFinalKey(target, []byte{})
	if keyRequired2 != 0 {
		t.Errorf("Expected keyRequired=0 for empty user key, got %d", keyRequired2)
	}
	if key1 != key2 {
		t.Errorf("Keys should be same for nil and empty user key")
	}

	// Test case 3: With user key
	userKey := []byte("test passphrase")
	key3, keyRequired3 := DeriveFinalKey(target, userKey)
	if keyRequired3 != 1 {
		t.Errorf("Expected keyRequired=1 for non-empty user key, got %d", keyRequired3)
	}

	// Should be different from puzzle-only key
	if key1 == key3 {
		t.Errorf("Keys should be different when user key is provided")
	}

	// Test case 4: Same user key should produce same result
	key4, keyRequired4 := DeriveFinalKey(target, userKey)
	if keyRequired4 != 1 {
		t.Errorf("Expected keyRequired=1, got %d", keyRequired4)
	}
	if key3 != key4 {
		t.Errorf("Same inputs should produce same key")
	}

	// Test case 5: Different user key should produce different result
	key5, _ := DeriveFinalKey(target, []byte("different passphrase"))
	if key3 == key5 {
		t.Errorf("Different user keys should produce different final keys")
	}
}

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

func TestEncryptDecryptKey(t *testing.T) {
	encryptionKey := [32]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
		17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32}

	keyToEncrypt := [32]byte{32, 31, 30, 29, 28, 27, 26, 25, 24, 23, 22, 21, 20, 19, 18, 17,
		16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1}

	// Encrypt key
	encKey, nonce, err := EncryptKey(encryptionKey, keyToEncrypt)
	if err != nil {
		t.Fatalf("EncryptKey failed: %v", err)
	}

	// Decrypt key
	decryptedKey, err := DecryptKey(encryptionKey, encKey, nonce)
	if err != nil {
		t.Fatalf("DecryptKey failed: %v", err)
	}

	// Should match original
	if decryptedKey != keyToEncrypt {
		t.Errorf("Decrypted key doesn't match original")
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

func TestDecryptKeyWithWrongKey(t *testing.T) {
	key1 := [32]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
		17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32}
	key2 := [32]byte{32, 31, 30, 29, 28, 27, 26, 25, 24, 23, 22, 21, 20, 19, 18, 17,
		16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1}

	keyToEncrypt := [32]byte{100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115,
		116, 117, 118, 119, 120, 121, 122, 123, 124, 125, 126, 127, 128, 129, 130, 131}

	// Encrypt with key1
	encKey, nonce, err := EncryptKey(key1, keyToEncrypt)
	if err != nil {
		t.Fatalf("EncryptKey failed: %v", err)
	}

	// Try to decrypt with key2 (should fail)
	_, err = DecryptKey(key2, encKey, nonce)
	if err == nil {
		t.Errorf("DecryptKey should fail with wrong key")
	}
}
