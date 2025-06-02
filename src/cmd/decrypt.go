package cmd

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"cryptotimed/src/crypto"
	"cryptotimed/src/utils"
)

// DecryptCommand handles the decrypt subcommand
func DecryptCommand(args []string) error {
	fs := flag.NewFlagSet("decrypt", flag.ExitOnError)

	var (
		inputFile  = fs.String("input", "", "Encrypted file to decrypt (required)")
		keyInput   = fs.String("key", "", "Passphrase or @file:path (required if file was encrypted with key)")
		outputFile = fs.String("output", "", "Output file (default: removes .locked extension)")
	)

	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s decrypt --input FILE [--key KEY] [--output FILE]\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "\nDecrypt a file encrypted with RSA time-lock puzzle\n\n")
		fmt.Fprintf(os.Stderr, "Options:\n")
		fs.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nExamples:\n")
		fmt.Fprintf(os.Stderr, "  %s decrypt --input document.pdf.locked\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s decrypt --input document.pdf.locked --key \"my passphrase\"\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s decrypt --input document.pdf.locked --key @file:keyfile.txt\n", os.Args[0])
	}

	if err := fs.Parse(args); err != nil {
		return err
	}

	// Validate required arguments
	if *inputFile == "" {
		fs.Usage()
		return fmt.Errorf("--input is required")
	}

	// Determine output file name
	if *outputFile == "" {
		if strings.HasSuffix(*inputFile, ".locked") {
			*outputFile = strings.TrimSuffix(*inputFile, ".locked")
		} else {
			*outputFile = *inputFile + ".decrypted"
		}
	}

	// Read encrypted file
	fmt.Printf("Reading encrypted file: %s\n", *inputFile)
	ef, err := utils.ReadEncryptedFile(*inputFile)
	if err != nil {
		return fmt.Errorf("failed to read encrypted file: %v", err)
	}

	// Check if key is required
	if ef.KeyRequired == 1 && *keyInput == "" {
		return fmt.Errorf("this file requires a key to decrypt (use --key)")
	}
	if ef.KeyRequired == 0 && *keyInput != "" {
		fmt.Printf("Warning: key provided but file was encrypted without key (ignoring key)\n")
		*keyInput = ""
	}

	// Parse key input
	userKeyRaw, err := utils.ParseKeyInput(*keyInput)
	if err != nil {
		return fmt.Errorf("failed to parse key input: %v", err)
	}

	// Extract puzzle from encrypted file
	puzzle := utils.PuzzleFromEncryptedFile(ef)

	// If this file uses password-based G derivation, we need to derive G from the password
	if ef.Version >= 2 && ef.KeyRequired == 1 {
		if len(userKeyRaw) == 0 {
			return fmt.Errorf("password required for this file")
		}

		// Derive G from password + salt using app-defined KDF parameters
		derivedG, err := crypto.DeriveBaseFromPassword(userKeyRaw, ef.Salt, puzzle.KdfParams, puzzle.N)
		if err != nil {
			return fmt.Errorf("failed to derive puzzle base from password: %v", err)
		}
		puzzle.G = derivedG
	}

	fmt.Printf("Solving time-lock puzzle (%d sequential squarings)...\n", ef.WorkFactor)

	// Create progress bar
	progressBar := utils.NewProgressBar(ef.WorkFactor)

	// Solve the puzzle with progress tracking
	target := crypto.SolvePuzzle(puzzle, func(done uint64) {
		progressBar.Update(done)
	})
	progressBar.Finish()

	fmt.Printf("Puzzle solved!\n")

	// Derive decryption key directly from puzzle target
	decryptionKey := crypto.DerivePuzzleKey(target)

	// Decrypt the data directly
	fmt.Printf("Decrypting data...\n")
	plaintext, err := crypto.DecryptData(decryptionKey, ef.Data)
	if err != nil {
		return fmt.Errorf("failed to decrypt data (wrong passphrase?): %v", err)
	}

	// Write decrypted file
	fmt.Printf("Writing decrypted file: %s\n", *outputFile)
	if err := utils.WriteFile(*outputFile, plaintext); err != nil {
		return fmt.Errorf("failed to write decrypted file: %v", err)
	}

	fmt.Printf("Decryption complete!\n")
	fmt.Printf("Input file: %s\n", *inputFile)
	fmt.Printf("Output file: %s (%d bytes)\n", *outputFile, len(plaintext))
	fmt.Printf("Work factor: %d sequential squarings\n", ef.WorkFactor)

	return nil
}
