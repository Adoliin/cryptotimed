package crypto

// tlp.go implements RSA trapdoor time‑lock puzzle generation and solving.
//
// It provides two high‑level entry points:
//   - GeneratePuzzle: create a fresh puzzle (N, g, t, target) using the trapdoor φ(N)
//     so that encryption is instant.
//   - SolvePuzzle:    sequentially square g modulo N exactly t times to recover the
//     same target without knowledge of φ(N).  This is inherently sequential and
//     cannot be parallelised under current knowledge.
//
// The module purposefully does NOT include any file‑format or ChaCha20 logic; those
// live in encryption.go and higher layers.  Only pure math lives here so the code
// is easy to unit‑test and to reuse.

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"errors"
	"io"
	"math/big"
)

const (
	// DefaultModulusBits is the default RSA modulus size used by GeneratePuzzle
	// when no custom size is requested.
	DefaultModulusBits = 2048

	// rsa2048Bytes is the length in bytes of a 2048‑bit modulus or element.
	rsa2048Bytes = DefaultModulusBits / 8
)

// Puzzle encapsulates all public information necessary to solve a time‑lock
// puzzle.  All fields are public so that callers can marshal/unmarshal as they
// wish –  tlp.go stays agnostic to any particular on‑disk format.
//
//   N, G, and Target are never nil (GeneratePuzzle guarantees this).  Target is
//   the result of raising G to 2^T mod N, _computed with_ the trapdoor; anyone
//   without φ(N) must call SolvePuzzle to recompute it.
//
// Only the encryptor ever needs φ(N); it is held transiently inside
// GeneratePuzzle and never leaves that function.
//
// NOTE: The puzzle assumes that N is an honest‑generated RSA modulus.  If the
// factors of N are leaked, the puzzle collapses.
//
// # Security
//
// Callers SHOULD discard the returned *rsa.PrivateKey (or at least its Primes)
// once GeneratePuzzle returns if they do not need it elsewhere, to minimise the
// window during which the trapdoor exists in memory.
//
// # Thread safety
//
// The struct itself is immutable after creation and therefore read‑only safe for
// concurrent use.
//
//go:generate go test ./...

type Puzzle struct {
	N      *big.Int // RSA modulus
	G      *big.Int // random base, gcd(G, N) = 1
	T      uint64   // number of sequential squarings
	Target *big.Int // G^{2^T} mod N (the solution)
}

// GeneratePuzzle creates a new RSA trapdoor time‑lock puzzle that requires ~T
// modular squarings to solve without knowledge of φ(N).
//
//	t     – number of sequential squarings required of the solver.
//
// The function returns the public puzzle and, separately, the private key (so
// that callers _may_ re‑use N or its factors if they wish).  Most applications
// will throw the private key away immediately.
func GeneratePuzzle(t uint64) (Puzzle, *rsa.PrivateKey, error) {
    bits := DefaultModulusBits
    randR := rand.Reader
	if bits < 1024 {
		return Puzzle{}, nil, errors.New("RSA modulus too small for security")
	}
	if randR == nil {
		randR = rand.Reader
	}

	// 1. Generate a fresh RSA key.
	priv, err := rsa.GenerateKey(randR, bits)
	if err != nil {
		return Puzzle{}, nil, err
	}
	N := new(big.Int).Set(priv.N) // defensive copy –  caller owns Puzzle

	// 2. Compute φ(N) = (p‑1)(q‑1).  We only need it temporarily.
	if len(priv.Primes) < 2 {
		return Puzzle{}, nil, errors.New("invalid RSA key: missing primes")
	}
	pMinus1 := new(big.Int).Sub(priv.Primes[0], big.NewInt(1))
	qMinus1 := new(big.Int).Sub(priv.Primes[1], big.NewInt(1))
	phiN := new(big.Int).Mul(pMinus1, qMinus1)

	// 3. Pick random base g∈[2,N‑2] with gcd(g,N)=1.
	G, err := randomCoprime(randR, N)
	if err != nil {
		return Puzzle{}, nil, err
	}

	// 4. Compute e = 2^T mod φ(N) efficiently (O(log T)).
	e := powTwoMod(phiN, t)

	// 5. target = g^e mod N – fast **because** we reduced the exponent modulo φ(N).
	Target := new(big.Int).Exp(G, e, N)

	return Puzzle{N: N, G: G, T: t, Target: Target}, priv, nil
}

// SolvePuzzle computes g^{2^T} mod N by T sequential squarings, returning the
// result.  The work is strictly sequential; each square depends on the
// previous value so cannot be parallelised with known techniques.
//
// A caller may pass an optional progress callback.  The callback is invoked
// whenever another `step` squarings have completed (see implementation for
// constant step size) or when the computation finishes.  It receives the number
// of squarings performed so far (in the range 1…T).
func SolvePuzzle(p Puzzle, progress func(done uint64)) *big.Int {
	result := new(big.Int).Set(p.G)
	modulus := p.N

	const step uint64 = 1 << 20 // call progress roughly every million steps

	for i := uint64(0); i < p.T; i++ {
		// result = result^2 mod N
		result.Mul(result, result)
		result.Mod(result, modulus)

		if progress != nil {
			if (i+1)%step == 0 || i+1 == p.T {
				progress(i + 1)
			}
		}
	}
	return result
}

// DerivePuzzleKey returns SHA‑256(target) as a fixed 32‑byte array suitable for
// use as a symmetric key (e.g. for ChaCha20).
func DerivePuzzleKey(target *big.Int) [32]byte {
	// target.Bytes() is big‑endian with no leading zero padding; make it 0‑padded
	// to rsa2048Bytes so that the mapping is injective across moduli of the same
	// size.
	buf := target.FillBytes(make([]byte, rsa2048Bytes))
	return sha256.Sum256(buf)
}

// randomCoprime chooses a uniform random integer g in [2, N‑2] such that
// gcd(g,N)=1.  It may loop a few times but the expected number of iterations is
// tiny for RSA moduli because most numbers are coprime to N.
func randomCoprime(r io.Reader, N *big.Int) (*big.Int, error) {
	two := big.NewInt(2)
	max := new(big.Int).Sub(N, two) // upper bound (inclusive) is N‑2 – ok because Int is non‑neg

	for {
		g, err := rand.Int(r, max)
		if err != nil {
			return nil, err
		}
		g.Add(g, two) // shift into [2, N‑2]

		// Ensure gcd(g,N) = 1.
		if new(big.Int).GCD(nil, nil, g, N).Cmp(big.NewInt(1)) == 0 {
			return g, nil
		}
	}
}

// powTwoMod returns 2^t mod m using binary exponentiation.  It runs in
// O(log t) multiplications – negligible compared to other costs.
func powTwoMod(m *big.Int, t uint64) *big.Int {
	res := big.NewInt(1)
	base := big.NewInt(2)

	for e := t; e > 0; e >>= 1 {
		if e&1 == 1 {
			res.Mul(res, base)
			res.Mod(res, m)
		}
		base.Mul(base, base)
		base.Mod(base, m)
	}
	return res
}

// Helper/testing functions ////////////////////////////////////////////////////

// SequentialSquaring performs one modular square – extracted to make unit tests
// easier and to micro‑benchmark constant‑time performance.
func SequentialSquaring(x, N *big.Int) *big.Int {
	return new(big.Int).Mod(new(big.Int).Mul(x, x), N)
}
