package types

// Rsa2048Bytes is the length in bytes of a 2048-bit RSA modulus
const Rsa2048Bytes = 256

// EncryptedFile represents the binary format of an encrypted file with time-lock puzzle
type EncryptedFile struct {
	Version     uint32             // format version
	WorkFactor  uint64             // t (number of squarings, from --work)
	ModulusN    [Rsa2048Bytes]byte // RSA modulus N
	BaseG       [Rsa2048Bytes]byte // base g
	KeyRequired uint8              // 0 = puzzle-only, 1 = puzzle + user key
	EncKey      [48]byte           // ChaCha20-Poly1305 encrypted K (32 B + 16 B auth tag)
	Nonce       [12]byte           // Nonce for EncKey encryption
	Data        []byte             // ChaCha20-Poly1305 ciphertext
}

// FileHeader contains the fixed-size header portion of EncryptedFile
type FileHeader struct {
	Version     uint32
	WorkFactor  uint64
	ModulusN    [Rsa2048Bytes]byte
	BaseG       [Rsa2048Bytes]byte
	KeyRequired uint8
	EncKey      [48]byte
	Nonce       [12]byte
}

const (
	// CurrentVersion is the current file format version
	CurrentVersion = 1

	// HeaderSize is the size of the fixed header in bytes
	HeaderSize = 4 + 8 + Rsa2048Bytes + Rsa2048Bytes + 1 + 48 + 12
)
