package main

import (
	"fmt"
	"os"

	"cryptotimed/src/cmd"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	command := os.Args[1]
	args := os.Args[2:]

	var err error
	switch command {
	case "encrypt":
		err = cmd.EncryptCommand(args)
	case "decrypt":
		err = cmd.DecryptCommand(args)
	case "benchmark":
		err = cmd.BenchmarkCommand(args)
	case "check":
		err = cmd.CheckCommand(args)
	case "help", "-h", "--help":
		printUsage()
		return
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n\n", command)
		printUsage()
		os.Exit(1)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Printf("cryptotimed - RSA Time-Lock Puzzle Encryption Tool\n\n")
	fmt.Printf("Usage:\n")
	fmt.Printf("  %s <command> [options]\n\n", os.Args[0])
	fmt.Printf("Commands:\n")
	fmt.Printf("  encrypt     Encrypt a file with time-lock puzzle\n")
	fmt.Printf("  decrypt     Decrypt a time-locked file\n")
	fmt.Printf("  check       Inspect an encrypted file and show metadata\n")
	fmt.Printf("  benchmark   Benchmark modular squaring performance\n")
	fmt.Printf("  help        Show this help message\n\n")
	fmt.Printf("Examples:\n")
	fmt.Printf("  %s encrypt --input document.pdf --work 81000000\n", os.Args[0])
	fmt.Printf("  %s encrypt --input document.pdf --work 81000000 --key \"passphrase\"\n", os.Args[0])
	fmt.Printf("  %s decrypt --input document.pdf.locked\n", os.Args[0])
	fmt.Printf("  %s decrypt --input document.pdf.locked --key \"passphrase\"\n", os.Args[0])
	fmt.Printf("  %s check --input document.pdf.locked\n", os.Args[0])
	fmt.Printf("  %s benchmark\n", os.Args[0])
	fmt.Printf("\nFor detailed help on a command, use:\n")
	fmt.Printf("  %s <command> --help\n", os.Args[0])
}
