package crypto

import (
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"math/big"

	"golang.org/x/crypto/chacha20poly1305"
)

// DeriveFinalKey returns the 32-byte ChaCha20 key used to encrypt K.
// puzzleTarget := SolvePuzzle(...)
// userKeyRaw   := optional user-supplied byte slice from the --key flag.
// If userKeyRaw is empty, returns DerivePuzzleKey(puzzleTarget) and sets keyRequired = 0.
// Otherwise returns XOR(DerivePuzzleKey(puzzleTarget), SHA256(userKeyRaw)) and sets keyRequired = 1.
func DeriveFinalKey(puzzleTarget *big.Int, userKeyRaw []byte) (key [32]byte, keyRequired uint8) {
	puzzleKey := DerivePuzzleKey(puzzleTarget)

	if len(userKeyRaw) == 0 {
		return puzzleKey, 0
	}

	// Hash the user key to ensure uniform length and entropy
	userKeyHash := sha256.Sum256(userKeyRaw)

	// XOR combine the puzzle key with the user key hash
	for i := 0; i < 32; i++ {
		key[i] = puzzleKey[i] ^ userKeyHash[i]
	}

	return key, 1
}

// EncryptData encrypts plaintext using ChaCha20-Poly1305 with the given key.
// Returns ciphertext (including authentication tag).
func EncryptData(key [32]byte, plaintext []byte) ([]byte, error) {
	aead, err := chacha20poly1305.New(key[:])
	if err != nil {
		return nil, err
	}

	// Generate random nonce
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}

	// Encrypt and authenticate
	ciphertext := aead.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}

// DecryptData decrypts ciphertext using ChaCha20-Poly1305 with the given key.
// The ciphertext should include the nonce at the beginning.
func DecryptData(key [32]byte, ciphertext []byte) ([]byte, error) {
	aead, err := chacha20poly1305.New(key[:])
	if err != nil {
		return nil, err
	}

	if len(ciphertext) < aead.NonceSize() {
		return nil, errors.New("ciphertext too short")
	}

	nonce := ciphertext[:aead.NonceSize()]
	ciphertext = ciphertext[aead.NonceSize():]

	plaintext, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

// EncryptKey encrypts a 32-byte symmetric key using ChaCha20-Poly1305 with the given encryption key.
// Returns the encrypted key with auth tag (48 bytes total) and the nonce separately.
func EncryptKey(encryptionKey [32]byte, keyToEncrypt [32]byte) ([48]byte, [12]byte, error) {
	aead, err := chacha20poly1305.New(encryptionKey[:])
	if err != nil {
		var result [48]byte
		var nonce [12]byte
		return result, nonce, err
	}

	// Generate random nonce
	var nonce [12]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		var result [48]byte
		return result, nonce, err
	}

	// Encrypt the key (32 bytes + 16 bytes auth tag = 48 bytes)
	encrypted := aead.Seal(nil, nonce[:], keyToEncrypt[:], nil)

	if len(encrypted) != 48 {
		var result [48]byte
		return result, nonce, errors.New("unexpected encrypted key length")
	}

	var result [48]byte
	copy(result[:], encrypted)

	return result, nonce, nil
}

// DecryptKey decrypts a 32-byte symmetric key using ChaCha20-Poly1305 with the given decryption key.
func DecryptKey(decryptionKey [32]byte, encryptedKey [48]byte, nonce [12]byte) ([32]byte, error) {
	var result [32]byte

	aead, err := chacha20poly1305.New(decryptionKey[:])
	if err != nil {
		return result, err
	}

	decrypted, err := aead.Open(nil, nonce[:], encryptedKey[:], nil)
	if err != nil {
		return result, err
	}

	if len(decrypted) != 32 {
		return result, errors.New("decrypted key has wrong length")
	}

	copy(result[:], decrypted)
	return result, nil
}
