package types

// Rsa2048Bytes is the length in bytes of a 2048-bit RSA modulus
const Rsa2048Bytes = 256

// EncryptedFile represents the binary format of an encrypted file with time-lock puzzle
type EncryptedFile struct {
	Version     uint32             // format version
	WorkFactor  uint64             // t (number of squarings, from --work)
	ModulusN    [Rsa2048Bytes]byte // RSA modulus N
	BaseG       [Rsa2048Bytes]byte // base g (now password-derived if KeyRequired=1)
	KeyRequired uint8              // 0 = puzzle-only, 1 = puzzle + user key
	Salt        [16]byte           // random salt for password-based G derivation (only if KeyRequired=1)
	KdfID       uint8              // KDF identifier: 0=none, 1=Argon2id
	KdfParams   [8]byte            // KDF parameters (memory cost, time cost, etc.)
	Data        []byte             // ChaCha20-Poly1305 ciphertext (includes nonce)
}

// FileHeader contains the fixed-size header portion of EncryptedFile
type FileHeader struct {
	Version     uint32
	WorkFactor  uint64
	ModulusN    [Rsa2048Bytes]byte
	BaseG       [Rsa2048Bytes]byte
	KeyRequired uint8
	Salt        [16]byte
	KdfID       uint8
	KdfParams   [8]byte
}

const (
	// CurrentVersion is the current file format version
	CurrentVersion = 2

	// HeaderSize is the size of the fixed header in bytes
	// 4 (Version) + 8 (WorkFactor) + 256 (ModulusN) + 256 (BaseG) + 1 (KeyRequired) +
	// 16 (Salt) + 1 (KdfID) + 8 (KdfParams)
	HeaderSize = 4 + 8 + Rsa2048Bytes + Rsa2048Bytes + 1 + 16 + 1 + 8

	// KDF identifiers
	KdfNone     = 0 // No KDF (legacy or puzzle-only)
	KdfArgon2id = 1 // Argon2id
)
