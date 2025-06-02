# CryptoTimed - RSA Time-Lock Puzzle Encryption Tool

A command-line tool that implements RSA trapdoor time-lock puzzles for asymmetric time-delayed encryption. This allows you to encrypt files that can only be decrypted after a specified amount of computational work (time delay).

## Features

- **Instant encryption** using RSA trapdoor for the encryptor
- **Deterministic work factor** - decryption requires exactly `t` sequential modular squarings
- **Optional dual-factor protection** - combine time-lock with a user passphrase
- **No parallel speed-up** - the work is inherently sequential
- **Progress tracking** during decryption
- **Benchmarking** to estimate work factors for desired delays

## Installation

```bash
go build -o cryptotimed src/main.go
```

## Usage

### Encrypt a file (puzzle-only)
```bash
./cryptotimed encrypt --input document.pdf --work 81000000
```

### Encrypt a file with passphrase
```bash
./cryptotimed encrypt --input document.pdf --work 81000000 --key "my secret passphrase"
```

### Encrypt with key from file
```bash
./cryptotimed encrypt --input document.pdf --work 81000000 --key @file:keyfile.txt
```

### Decrypt a file
```bash
./cryptotimed decrypt --input document.pdf.locked
```

### Decrypt with passphrase
```bash
./cryptotimed decrypt --input document.pdf.locked --key "my secret passphrase"
```

### Benchmark performance
```bash
./cryptotimed benchmark
```

### Get help
```bash
./cryptotimed help
./cryptotimed encrypt --help
```

## How It Works

1. **Encryption**: 
   - Generates a fresh RSA key pair and time-lock puzzle
   - Uses the RSA trapdoor to instantly compute the puzzle solution
   - Derives encryption keys from the puzzle solution
   - Encrypts data with ChaCha20-Poly1305
   - Stores puzzle parameters and encrypted data

2. **Decryption**:
   - Reads puzzle parameters from the encrypted file
   - Performs `t` sequential modular squarings to solve the puzzle
   - Derives the same encryption keys from the solution
   - Decrypts the data

## Security

- **Time-lock security**: Based on the assumption that sequential modular squaring cannot be parallelized
- **RSA security**: Relies on the difficulty of factoring large RSA moduli
- **Authenticated encryption**: Uses ChaCha20-Poly1305 for data encryption with authentication
- **Key derivation**: Uses SHA-256 for deterministic key derivation from puzzle solutions

## File Format

The encrypted file contains:
- Version (4 bytes)
- Work factor (8 bytes) 
- RSA modulus N (256 bytes)
- Base G (256 bytes)
- Key required flag (1 byte)
- Encrypted data key (48 bytes)
- Nonce (12 bytes)
- Encrypted data (variable length)

## Performance

Use the benchmark command to measure your system's performance:

```bash
./cryptotimed benchmark --duration 10s --samples 3
```

This will help you choose appropriate work factors for desired delays.

## Examples

### 1-minute delay (approximate)
```bash
# First benchmark to get your system's rate
./cryptotimed benchmark

# If benchmark shows ~500,000 ops/sec, use 30,000,000 for ~1 minute
./cryptotimed encrypt --input secret.txt --work 30000000
```

### Dual-factor encryption
```bash
# Encrypt with both time-lock and passphrase
./cryptotimed encrypt --input secret.txt --work 30000000 --key "strong passphrase"

# Decryption requires both solving the puzzle AND knowing the passphrase
./cryptotimed decrypt --input secret.txt.locked --key "strong passphrase"
```

## Testing

Run the test suite:

```bash
go test ./src/... -v
```

## Architecture

- `src/main.go` - CLI entry point
- `src/cmd/` - Command-line interface (argument parsing, validation, help)
- `src/operations/` - Business logic for core operations (encrypt, decrypt, benchmark)
- `src/crypto/` - Cryptographic primitives (TLP, ChaCha20-Poly1305)
- `src/utils/` - File I/O and progress utilities
- `src/types/` - Data structures

## License

This implementation is for educational and research purposes. The RSA time-lock puzzle concept was introduced by Rivest, Shamir, and Wagner in 1996.