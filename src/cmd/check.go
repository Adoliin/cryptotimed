package cmd

import (
	"flag"
	"fmt"
	"os"

	"cryptotimed/src/operations"
)

// CheckCommand handles the check subcommand
func CheckCommand(args []string) error {
	fs := flag.NewFlagSet("check", flag.ExitOnError)

	var (
		inputFile = fs.String("input", "", "Encrypted file to inspect (required)")
	)

	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s check --input FILE\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "\nInspect an encrypted file and display its metadata\n\n")
		fmt.Fprintf(os.Stderr, "Options:\n")
		fs.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nExamples:\n")
		fmt.Fprintf(os.Stderr, "  %s check --input document.pdf.locked\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s check --input secret.txt.locked\n", os.Args[0])
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
	opts := operations.CheckOptions{
		InputFile: *inputFile,
	}

	// Perform the check operation
	result, err := operations.CheckFile(opts)
	if err != nil {
		return err
	}

	// Display results in a pretty format
	printCheckResults(result)

	return nil
}

// printCheckResults displays the check results in a formatted way
func printCheckResults(result *operations.CheckResult) {
	fmt.Printf("═══════════════════════════════════════════════════════════════════════════════\n")
	fmt.Printf("                          ENCRYPTED FILE METADATA\n")
	fmt.Printf("═══════════════════════════════════════════════════════════════════════════════\n")
	fmt.Printf("\n")

	// File Information
	fmt.Printf("📁 FILE INFORMATION\n")
	fmt.Printf("   File:           %s\n", result.InputFile)
	fmt.Printf("   Total Size:     %d bytes (%.2f KB)\n", result.TotalFileSize, float64(result.TotalFileSize)/1024)
	fmt.Printf("   Data Size:      %d bytes (%.2f KB)\n", result.DataSize, float64(result.DataSize)/1024)
	fmt.Printf("   Format Version: %d\n", result.Version)
	fmt.Printf("\n")

	// Security Information
	fmt.Printf("🔒 SECURITY INFORMATION\n")
	fmt.Printf("   Security Level: %s\n", result.SecurityLevel)
	fmt.Printf("   Key Required:   %s\n", formatBool(result.KeyRequired))
	if result.KeyRequired {
		fmt.Printf("   Salt:           %x\n", result.Salt)
	}
	fmt.Printf("\n")

	// Time-Lock Puzzle Information
	fmt.Printf("⏰ TIME-LOCK PUZZLE\n")
	fmt.Printf("   Work Factor:    %s operations\n", formatNumber(result.WorkFactor))
	fmt.Printf("   Estimated Time: %s*\n", result.EstimatedTime)
	fmt.Printf("\n")

	// Cryptographic Parameters
	fmt.Printf("🔢 CRYPTOGRAPHIC PARAMETERS\n")
	fmt.Printf("   RSA Modulus (N):\n")
	fmt.Printf("     Bit Length:   %d bits\n", result.ModulusN.BitLen())
	fmt.Printf("     Hex (first 64 chars): %s...\n", fmt.Sprintf("%x", result.ModulusN)[:64])
	fmt.Printf("\n")
	fmt.Printf("   Base (G):\n")
	fmt.Printf("     Bit Length:   %d bits\n", result.BaseG.BitLen())
	fmt.Printf("     Hex (first 64 chars): %s...\n", fmt.Sprintf("%x", result.BaseG)[:64])
	fmt.Printf("\n")

	// Footer note
	fmt.Printf("───────────────────────────────────────────────────────────────────────────────\n")
	fmt.Printf("* Estimated time is approximate and depends on hardware performance\n")
	fmt.Printf("  Use 'cryptotimed benchmark' to get more accurate estimates for your system\n")
}

// formatBool formats a boolean value for display
func formatBool(b bool) string {
	if b {
		return "Yes"
	}
	return "No"
}

// formatNumber formats large numbers with commas for readability
func formatNumber(n uint64) string {
	str := fmt.Sprintf("%d", n)
	if len(str) <= 3 {
		return str
	}

	// Add commas every 3 digits from the right
	result := ""
	for i, char := range str {
		if i > 0 && (len(str)-i)%3 == 0 {
			result += ","
		}
		result += string(char)
	}
	return result
}
