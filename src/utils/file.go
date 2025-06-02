package utils

import (
	"bytes"
	"encoding/binary"
	"io"
	"math/big"
	"os"

	"cryptotimed/src/crypto"
	"cryptotimed/src/types"
)

// ReadFile reads the entire contents of a file
func ReadFile(filename string) ([]byte, error) {
	return os.ReadFile(filename)
}

// WriteFile writes data to a file, creating it if necessary
func WriteFile(filename string, data []byte) error {
	return os.WriteFile(filename, data, 0644)
}

// WriteEncryptedFile writes an EncryptedFile structure to disk in binary format
func WriteEncryptedFile(filename string, ef *types.EncryptedFile) error {
	var buf bytes.Buffer

	// Write header fields in binary format
	if err := binary.Write(&buf, binary.LittleEndian, ef.Version); err != nil {
		return err
	}
	if err := binary.Write(&buf, binary.LittleEndian, ef.WorkFactor); err != nil {
		return err
	}
	if err := binary.Write(&buf, binary.LittleEndian, ef.ModulusN); err != nil {
		return err
	}
	if err := binary.Write(&buf, binary.LittleEndian, ef.BaseG); err != nil {
		return err
	}
	if err := binary.Write(&buf, binary.LittleEndian, ef.KeyRequired); err != nil {
		return err
	}
	if err := binary.Write(&buf, binary.LittleEndian, ef.Salt); err != nil {
		return err
	}

	// Write data length and data
	dataLen := uint64(len(ef.Data))
	if err := binary.Write(&buf, binary.LittleEndian, dataLen); err != nil {
		return err
	}
	if _, err := buf.Write(ef.Data); err != nil {
		return err
	}

	return WriteFile(filename, buf.Bytes())
}

// ReadEncryptedFile reads an EncryptedFile structure from disk
func ReadEncryptedFile(filename string) (*types.EncryptedFile, error) {
	data, err := ReadFile(filename)
	if err != nil {
		return nil, err
	}

	buf := bytes.NewReader(data)
	ef := &types.EncryptedFile{}

	// Read version first to determine file format
	if err := binary.Read(buf, binary.LittleEndian, &ef.Version); err != nil {
		return nil, err
	}

	// Read common fields
	if err := binary.Read(buf, binary.LittleEndian, &ef.WorkFactor); err != nil {
		return nil, err
	}
	if err := binary.Read(buf, binary.LittleEndian, &ef.ModulusN); err != nil {
		return nil, err
	}
	if err := binary.Read(buf, binary.LittleEndian, &ef.BaseG); err != nil {
		return nil, err
	}
	if err := binary.Read(buf, binary.LittleEndian, &ef.KeyRequired); err != nil {
		return nil, err
	}

	if err := binary.Read(buf, binary.LittleEndian, &ef.Salt); err != nil {
		return nil, err
	}

	// Read data length
	var dataLen uint64
	if err := binary.Read(buf, binary.LittleEndian, &dataLen); err != nil {
		return nil, err
	}

	// Read data
	ef.Data = make([]byte, dataLen)
	if _, err := io.ReadFull(buf, ef.Data); err != nil {
		return nil, err
	}

	return ef, nil
}

// PuzzleFromEncryptedFile extracts a crypto.Puzzle from an EncryptedFile
func PuzzleFromEncryptedFile(ef *types.EncryptedFile) crypto.Puzzle {
	N := new(big.Int).SetBytes(ef.ModulusN[:])
	G := new(big.Int).SetBytes(ef.BaseG[:])

	puzzle := crypto.Puzzle{
		N: N,
		G: G,
		T: ef.WorkFactor,
		// Target will be computed by SolvePuzzle
		Salt: ef.Salt,
	}

	// Set KDF parameters based on file version and KeyRequired flag
	if ef.KeyRequired == 1 {
		puzzle.KdfID = 1 // Argon2id
		puzzle.KdfParams = crypto.DefaultArgon2idParams
	}

	return puzzle
}

// PuzzleToBytes converts puzzle components to byte arrays for storage
func PuzzleToBytes(puzzle crypto.Puzzle) ([types.Rsa2048Bytes]byte, [types.Rsa2048Bytes]byte) {
	var nBytes, gBytes [types.Rsa2048Bytes]byte

	// Convert N to bytes (big-endian, zero-padded)
	nBytesSlice := puzzle.N.FillBytes(make([]byte, types.Rsa2048Bytes))
	copy(nBytes[:], nBytesSlice)

	// Convert G to bytes (big-endian, zero-padded)
	gBytesSlice := puzzle.G.FillBytes(make([]byte, types.Rsa2048Bytes))
	copy(gBytes[:], gBytesSlice)

	return nBytes, gBytes
}

// ParseKeyInput parses key input from CLI, supporting both direct strings and @file:path syntax
func ParseKeyInput(keyInput string) ([]byte, error) {
	if keyInput == "" {
		return nil, nil
	}

	// Check if it's a file reference (@file:path)
	if len(keyInput) > 6 && keyInput[:6] == "@file:" {
		filepath := keyInput[6:]
		return ReadFile(filepath)
	}

	// Direct string input - convert to bytes
	return []byte(keyInput), nil
}

// GetFileInfo returns file information
func GetFileInfo(filename string) (os.FileInfo, error) {
	return os.Stat(filename)
}
