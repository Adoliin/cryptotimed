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
	if err := binary.Write(&buf, binary.LittleEndian, ef.KdfID); err != nil {
		return err
	}
	if err := binary.Write(&buf, binary.LittleEndian, ef.KdfParams); err != nil {
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

	// Handle version-specific fields
	if ef.Version >= 2 {
		// Version 2+: includes salt and KDF parameters, no separate EncKey/Nonce
		if err := binary.Read(buf, binary.LittleEndian, &ef.Salt); err != nil {
			return nil, err
		}
		if err := binary.Read(buf, binary.LittleEndian, &ef.KdfID); err != nil {
			return nil, err
		}
		if err := binary.Read(buf, binary.LittleEndian, &ef.KdfParams); err != nil {
			return nil, err
		}
	} else {
		// Version 1: legacy format with EncKey/Nonce fields
		// Initialize with zero values (KdfID=0 means no KDF)
		ef.KdfID = types.KdfNone
		
		// Skip the old EncKey and Nonce fields (48 + 12 = 60 bytes)
		var encKey [48]byte
		var nonce [12]byte
		if err := binary.Read(buf, binary.LittleEndian, &encKey); err != nil {
			return nil, err
		}
		if err := binary.Read(buf, binary.LittleEndian, &nonce); err != nil {
			return nil, err
		}
		// Note: For Version 1 files, we'll need special handling in decrypt
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
		Salt:  ef.Salt,
		KdfID: ef.KdfID,
	}

	// Decode KDF parameters if present
	if ef.KdfID == types.KdfArgon2id {
		puzzle.KdfParams = crypto.DecodeKdfParams(ef.KdfParams)
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
