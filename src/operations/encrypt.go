package operations

import (
	"fmt"

	"cryptotimed/src/crypto"
	"cryptotimed/src/types"
	"cryptotimed/src/utils"
)

// EncryptOptions contains all the parameters needed for encryption
type EncryptOptions struct {
	InputFile  string
	WorkFactor uint64
	KeyInput   string
}

// EncryptResult contains the results of the encryption operation
type EncryptResult struct {
	InputFile     string
	OutputFile    string
	PlaintextSize int
	EncryptedSize int
	WorkFactor    uint64
	KeyRequired   bool
}

// EncryptFile performs the core encryption logic
func EncryptFile(opts EncryptOptions) (*EncryptResult, error) {
	// Parse key input
	userKeyRaw, err := utils.ParseKeyInput(opts.KeyInput)
	if err != nil {
		return nil, fmt.Errorf("failed to parse key input: %v", err)
	}

	// Read input file
	plaintext, err := utils.ReadFile(opts.InputFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read input file: %v", err)
	}

	// Generate time-lock puzzle
	puzzle, _, err := crypto.GeneratePuzzle(opts.WorkFactor, userKeyRaw)
	if err != nil {
		return nil, fmt.Errorf("failed to generate puzzle: %v", err)
	}

	// Derive encryption key directly from puzzle target
	encryptionKey := crypto.DerivePuzzleKey(puzzle.Target)

	// Determine if password was used (affects file format)
	var keyRequired uint8
	if len(userKeyRaw) > 0 {
		keyRequired = 1
	} else {
		keyRequired = 0
	}

	// Encrypt the data directly with the puzzle-derived key
	encryptedData, err := crypto.EncryptData(encryptionKey, plaintext)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt data: %v", err)
	}

	// Convert puzzle to byte arrays for storage
	nBytes, gBytes := utils.PuzzleToBytes(puzzle)

	// Create encrypted file structure
	ef := &types.EncryptedFile{
		Version:     types.CurrentVersion,
		WorkFactor:  opts.WorkFactor,
		ModulusN:    nBytes,
		BaseG:       gBytes,
		KeyRequired: keyRequired,
		Salt:        puzzle.Salt,
		Data:        encryptedData,
	}

	// Write encrypted file
	outputFile := opts.InputFile + ".locked"
	if err := utils.WriteEncryptedFile(outputFile, ef); err != nil {
		return nil, fmt.Errorf("failed to write encrypted file: %v", err)
	}

	return &EncryptResult{
		InputFile:     opts.InputFile,
		OutputFile:    outputFile,
		PlaintextSize: len(plaintext),
		EncryptedSize: types.HeaderSize + 8 + len(encryptedData),
		WorkFactor:    opts.WorkFactor,
		KeyRequired:   keyRequired == 1,
	}, nil
}
