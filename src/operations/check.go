package operations

import (
	"fmt"
	"math/big"

	"cryptotimed/src/utils"
)

// CheckOptions contains all the parameters needed for checking file metadata
type CheckOptions struct {
	InputFile string
}

// CheckResult contains the metadata extracted from an encrypted file
type CheckResult struct {
	InputFile     string
	Version       uint32
	WorkFactor    uint64
	ModulusN      *big.Int
	BaseG         *big.Int
	KeyRequired   bool
	Salt          [16]byte
	DataSize      int
	TotalFileSize int64
	EstimatedTime string
	SecurityLevel string
}

// CheckFile inspects an encrypted file and extracts its metadata
func CheckFile(opts CheckOptions) (*CheckResult, error) {
	// Read encrypted file
	ef, err := utils.ReadEncryptedFile(opts.InputFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read encrypted file: %v", err)
	}

	// Get file size
	fileInfo, err := utils.GetFileInfo(opts.InputFile)
	if err != nil {
		return nil, fmt.Errorf("failed to get file info: %v", err)
	}

	// Convert byte arrays to big.Int for display
	modulusN := new(big.Int).SetBytes(ef.ModulusN[:])
	baseG := new(big.Int).SetBytes(ef.BaseG[:])

	// Estimate time based on work factor (rough approximation)
	estimatedTime := estimateDecryptionTime(ef.WorkFactor)

	// Determine security level based on RSA key size
	securityLevel := determineSecurityLevel(modulusN)

	return &CheckResult{
		InputFile:     opts.InputFile,
		Version:       ef.Version,
		WorkFactor:    ef.WorkFactor,
		ModulusN:      modulusN,
		BaseG:         baseG,
		KeyRequired:   ef.KeyRequired == 1,
		Salt:          ef.Salt,
		DataSize:      len(ef.Data),
		TotalFileSize: fileInfo.Size(),
		EstimatedTime: estimatedTime,
		SecurityLevel: securityLevel,
	}, nil
}

// estimateDecryptionTime provides a rough estimate of decryption time
func estimateDecryptionTime(workFactor uint64) string {
	// Rough estimate: assume ~500,000 operations per second on average hardware
	// This is just an approximation and will vary significantly by hardware
	const avgOpsPerSecond = 500000

	estimatedSeconds := float64(workFactor) / avgOpsPerSecond

	if estimatedSeconds < 60 {
		return fmt.Sprintf("~%.1f seconds", estimatedSeconds)
	} else if estimatedSeconds < 3600 {
		minutes := estimatedSeconds / 60
		return fmt.Sprintf("~%.1f minutes", minutes)
	} else if estimatedSeconds < 86400 {
		hours := estimatedSeconds / 3600
		return fmt.Sprintf("~%.1f hours", hours)
	} else {
		days := estimatedSeconds / 86400
		return fmt.Sprintf("~%.1f days", days)
	}
}

// determineSecurityLevel determines security level based on RSA modulus size
func determineSecurityLevel(modulus *big.Int) string {
	bitLength := modulus.BitLen()

	switch {
	case bitLength >= 2048:
		return "High (RSA-2048+)"
	case bitLength >= 1024:
		return "Medium (RSA-1024+)"
	default:
		return "Low (RSA-<1024)"
	}
}
