package cmd

import (
	"crypto/rand"
	"flag"
	"fmt"
	"os"

	"cryptotimed/src/crypto"
	"cryptotimed/src/types"
	"cryptotimed/src/utils"
)

// EncryptCommand handles the encrypt subcommand
func EncryptCommand(args []string) error {
	fs := flag.NewFlagSet("encrypt", flag.ExitOnError)

	var (
		inputFile  = fs.String("input", "", "Input file to encrypt (required)")
		workFactor = fs.Uint64("work", 0, "Number of sequential squarings required (required)")
		keyInput   = fs.String("key", "", "Optional passphrase or @file:path")
	)

	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s encrypt --input FILE --work ITERATIONS [--key KEY]\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "\nEncrypt a file with RSA time-lock puzzle\n\n")
		fmt.Fprintf(os.Stderr, "Options:\n")
		fs.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nExamples:\n")
		fmt.Fprintf(os.Stderr, "  %s encrypt --input document.pdf --work 81000000\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s encrypt --input document.pdf --work 81000000 --key \"my passphrase\"\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s encrypt --input document.pdf --work 81000000 --key @file:keyfile.txt\n", os.Args[0])
	}

	if err := fs.Parse(args); err != nil {
		return err
	}

	// Validate required arguments
	if *inputFile == "" {
		fs.Usage()
		return fmt.Errorf("--input is required")
	}
	if *workFactor == 0 {
		fs.Usage()
		return fmt.Errorf("--work is required and must be > 0")
	}

	// Parse key input
	userKeyRaw, err := utils.ParseKeyInput(*keyInput)
	if err != nil {
		return fmt.Errorf("failed to parse key input: %v", err)
	}

	// Read input file
	fmt.Printf("Reading input file: %s\n", *inputFile)
	plaintext, err := utils.ReadFile(*inputFile)
	if err != nil {
		return fmt.Errorf("failed to read input file: %v", err)
	}

	// Generate time-lock puzzle
	fmt.Printf("Generating time-lock puzzle (work factor: %d)...\n", *workFactor)
	puzzle, _, err := crypto.GeneratePuzzle(*workFactor)
	if err != nil {
		return fmt.Errorf("failed to generate puzzle: %v", err)
	}

	// Derive final encryption key
	finalKey, keyRequired := crypto.DeriveFinalKey(puzzle.Target, userKeyRaw)

	// Generate random symmetric key for data encryption
	var dataKey [32]byte
	if _, err := rand.Read(dataKey[:]); err != nil {
		return fmt.Errorf("failed to generate data key: %v", err)
	}

	// Encrypt the data with the random key
	fmt.Printf("Encrypting data (%d bytes)...\n", len(plaintext))
	encryptedData, err := crypto.EncryptData(dataKey, plaintext)
	if err != nil {
		return fmt.Errorf("failed to encrypt data: %v", err)
	}

	// Encrypt the data key with the final key
	encKey, nonce, err := crypto.EncryptKey(finalKey, dataKey)
	if err != nil {
		return fmt.Errorf("failed to encrypt data key: %v", err)
	}

	// Convert puzzle to byte arrays for storage
	nBytes, gBytes := utils.PuzzleToBytes(puzzle)

	// Create encrypted file structure
	ef := &types.EncryptedFile{
		Version:     types.CurrentVersion,
		WorkFactor:  *workFactor,
		ModulusN:    nBytes,
		BaseG:       gBytes,
		KeyRequired: keyRequired,
		EncKey:      encKey,
		Nonce:       nonce,
		Data:        encryptedData,
	}

	// Write encrypted file
	outputFile := *inputFile + ".locked"
	fmt.Printf("Writing encrypted file: %s\n", outputFile)
	if err := utils.WriteEncryptedFile(outputFile, ef); err != nil {
		return fmt.Errorf("failed to write encrypted file: %v", err)
	}

	fmt.Printf("Encryption complete!\n")
	fmt.Printf("Input file: %s (%d bytes)\n", *inputFile, len(plaintext))
	fmt.Printf("Output file: %s (%d bytes)\n", outputFile, types.HeaderSize+8+len(encryptedData))
	fmt.Printf("Work factor: %d sequential squarings\n", *workFactor)
	if keyRequired == 1 {
		fmt.Printf("Key required: Yes (puzzle + passphrase)\n")
	} else {
		fmt.Printf("Key required: No (puzzle only)\n")
	}

	return nil
}
