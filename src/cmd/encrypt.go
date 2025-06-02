package cmd

import (
	"flag"
	"fmt"
	"os"

	"cryptotimed/src/operations"
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

	// Prepare options for the operation
	opts := operations.EncryptOptions{
		InputFile:  *inputFile,
		WorkFactor: *workFactor,
		KeyInput:   *keyInput,
	}

	// Display progress messages
	fmt.Printf("Reading input file: %s\n", *inputFile)
	fmt.Printf("Generating time-lock puzzle (work factor: %d)...\n", *workFactor)

	// Perform the encryption operation
	result, err := operations.EncryptFile(opts)
	if err != nil {
		return err
	}

	// Display results
	fmt.Printf("Encrypting data (%d bytes)...\n", result.PlaintextSize)
	fmt.Printf("Writing encrypted file: %s\n", result.OutputFile)
	fmt.Printf("Encryption complete!\n")
	fmt.Printf("Input file: %s (%d bytes)\n", result.InputFile, result.PlaintextSize)
	fmt.Printf("Output file: %s (%d bytes)\n", result.OutputFile, result.EncryptedSize)
	fmt.Printf("Work factor: %d sequential squarings\n", result.WorkFactor)
	if result.KeyRequired {
		fmt.Printf("Key required: Yes (puzzle + passphrase)\n")
	} else {
		fmt.Printf("Key required: No (puzzle only)\n")
	}

	return nil
}
