package cmd

import (
	"flag"
	"fmt"
	"os"

	"cryptotimed/src/operations"
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

	// Prepare options for the operation
	opts := operations.DecryptOptions{
		InputFile:  *inputFile,
		KeyInput:   *keyInput,
		OutputFile: *outputFile,
	}

	// Display initial progress messages
	fmt.Printf("Reading encrypted file: %s\n", *inputFile)

	// Read encrypted file to get work factor for progress display
	ef, err := utils.ReadEncryptedFile(*inputFile)
	if err != nil {
		return fmt.Errorf("failed to read encrypted file: %v", err)
	}

	// Check if key is required and provide warning if needed
	if ef.KeyRequired == 0 && *keyInput != "" {
		fmt.Printf("Warning: key provided but file was encrypted without key (ignoring key)\n")
	}

	fmt.Printf("Solving time-lock puzzle (%d sequential squarings)...\n", ef.WorkFactor)

	// Create progress bar
	progressBar := utils.NewProgressBar(ef.WorkFactor)

	// Perform the decryption operation with progress tracking
	result, err := operations.DecryptFile(opts, func(done uint64) {
		progressBar.Update(done)
	})
	if err != nil {
		return err
	}

	progressBar.Finish()

	// Display results
	fmt.Printf("Puzzle solved!\n")
	fmt.Printf("Decrypting data...\n")
	fmt.Printf("Writing decrypted file: %s\n", result.OutputFile)
	fmt.Printf("Decryption complete!\n")
	fmt.Printf("Input file: %s\n", result.InputFile)
	fmt.Printf("Output file: %s (%d bytes)\n", result.OutputFile, result.PlaintextSize)
	fmt.Printf("Work factor: %d sequential squarings\n", result.WorkFactor)

	return nil
}
