package operations

import (
	"fmt"
	"strings"

	"cryptotimed/src/crypto"
	"cryptotimed/src/utils"
)

// DecryptOptions contains all the parameters needed for decryption
type DecryptOptions struct {
	InputFile  string
	KeyInput   string
	OutputFile string
}

// DecryptResult contains the results of the decryption operation
type DecryptResult struct {
	InputFile     string
	OutputFile    string
	PlaintextSize int
	WorkFactor    uint64
}

// ProgressCallback is a function type for progress updates during puzzle solving
type ProgressCallback func(done uint64)

// DecryptFile performs the core decryption logic
func DecryptFile(opts DecryptOptions, progressCallback ProgressCallback) (*DecryptResult, error) {
	// Determine output file name if not provided
	outputFile := opts.OutputFile
	if outputFile == "" {
		if strings.HasSuffix(opts.InputFile, ".locked") {
			outputFile = strings.TrimSuffix(opts.InputFile, ".locked")
		} else {
			outputFile = opts.InputFile + ".decrypted"
		}
	}

	// Read encrypted file
	ef, err := utils.ReadEncryptedFile(opts.InputFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read encrypted file: %v", err)
	}

	// Check if key is required
	if ef.KeyRequired == 1 && opts.KeyInput == "" {
		return nil, fmt.Errorf("this file requires a key to decrypt (use --key)")
	}
	if ef.KeyRequired == 0 && opts.KeyInput != "" {
		// Warning: key provided but file was encrypted without key (ignoring key)
		opts.KeyInput = ""
	}

	// Parse key input
	userKeyRaw, err := utils.ParseKeyInput(opts.KeyInput)
	if err != nil {
		return nil, fmt.Errorf("failed to parse key input: %v", err)
	}

	// Extract puzzle from encrypted file
	puzzle := utils.PuzzleFromEncryptedFile(ef)

	// If this file uses password-based G derivation, we need to derive G from the password
	if ef.Version >= 2 && ef.KeyRequired == 1 {
		if len(userKeyRaw) == 0 {
			return nil, fmt.Errorf("password required for this file")
		}

		// Derive G from password + salt using app-defined KDF parameters
		derivedG, err := crypto.DeriveBaseFromPassword(userKeyRaw, ef.Salt, puzzle.KdfParams, puzzle.N)
		if err != nil {
			return nil, fmt.Errorf("failed to derive puzzle base from password: %v", err)
		}
		puzzle.G = derivedG
	}

	// Solve the puzzle with progress tracking
	target := crypto.SolvePuzzle(puzzle, progressCallback)

	// Derive decryption key directly from puzzle target
	decryptionKey := crypto.DerivePuzzleKey(target)

	// Decrypt the data directly
	plaintext, err := crypto.DecryptData(decryptionKey, ef.Data)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt data (wrong passphrase?): %v", err)
	}

	// Write decrypted file
	if err := utils.WriteFile(outputFile, plaintext); err != nil {
		return nil, fmt.Errorf("failed to write decrypted file: %v", err)
	}

	return &DecryptResult{
		InputFile:     opts.InputFile,
		OutputFile:    outputFile,
		PlaintextSize: len(plaintext),
		WorkFactor:    ef.WorkFactor,
	}, nil
}
