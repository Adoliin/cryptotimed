package crypto

import (
	"crypto/rand"
	"errors"

	"golang.org/x/crypto/chacha20poly1305"
)

// Note: DeriveFinalKey removed - we now use DerivePuzzleKey directly since
// password is integrated into the puzzle itself

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

// Note: EncryptKey and DecryptKey functions removed - we now encrypt data directly
// with the puzzle-derived key since password is integrated into the puzzle itself
