package crypto

import (
	"math/big"
	"testing"
)

// TestGenerateAndSolvePuzzle creates a full puzzle, solves it by sequential
// squaring and checks all invariants.
func TestGenerateAndSolvePuzzle(t *testing.T) {
	const squarings = 20 // keep unit‑test quick

	puzzle, priv, err := GeneratePuzzle(squarings, nil) // No password for test
	if err != nil {
		t.Fatalf("GeneratePuzzle failed: %v", err)
	}
	if puzzle.N.BitLen() != 2048 {
		t.Fatalf("unexpected modulus size %d", puzzle.N.BitLen())
	}

	// 1. Target must equal G^{2^T mod φ(N)} mod N.
	phiN := new(big.Int).Mul(
		new(big.Int).Sub(priv.Primes[0], big.NewInt(1)),
		new(big.Int).Sub(priv.Primes[1], big.NewInt(1)),
	)
	exp := powTwoMod(phiN, puzzle.T)
	expectedTarget := new(big.Int).Exp(puzzle.G, exp, puzzle.N)
	if expectedTarget.Cmp(puzzle.Target) != 0 {
		t.Fatalf("target mismatch: want %s got %s", expectedTarget, puzzle.Target)
	}

	// 2. Sequential solver must reproduce Target exactly.
	got := SolvePuzzle(puzzle, nil)
	if got.Cmp(puzzle.Target) != 0 {
		t.Fatalf("SolvePuzzle incorrect result\nwant: %s\n got: %s", puzzle.Target, got)
	}

	// 3. Key derivation must be deterministic and equal for both big.Int copies.
	k1 := DerivePuzzleKey(got)
	k2 := DerivePuzzleKey(puzzle.Target)
	if k1 != k2 {
		t.Fatalf("DerivePuzzleKey mismatch: %x vs %x", k1, k2)
	}
}

// TestPowTwoMod checks that powTwoMod returns the same value as regular
// exponentiation for a variety of moduli and exponents.
func TestPowTwoMod(t *testing.T) {
	tests := []struct {
		m int64
		t uint64
	}{
		{97, 0}, {97, 1}, {97, 2}, {97, 53}, {1019, 127},
	}
	two := big.NewInt(2)

	for _, tc := range tests {
		mod := big.NewInt(tc.m)
		want := new(big.Int).Exp(two, big.NewInt(int64(tc.t)), mod)
		got := powTwoMod(mod, tc.t)
		if got.Cmp(want) != 0 {
			t.Fatalf("2^%d mod %d wrong: want %s got %s", tc.t, tc.m, want, got)
		}
	}
}

// TestSequentialSquaring validates the helper against Exp(x,2).
func TestSequentialSquaring(t *testing.T) {
	N := big.NewInt(101 * 113) // arbitrary composite modulus
	x := big.NewInt(42)
	want := new(big.Int).Exp(x, big.NewInt(2), N)
	got := SequentialSquaring(x, N)
	if got.Cmp(want) != 0 {
		t.Fatalf("SequentialSquaring incorrect: want %s got %s", want, got)
	}
}

// TestProgressCallback confirms that the progress function is invoked at least
// once (for small T it will fire only on completion).
func TestProgressCallback(t *testing.T) {
	p := Puzzle{
		N: big.NewInt(17),
		G: big.NewInt(3),
		T: 5,
	}
	var calls int
	SolvePuzzle(p, func(done uint64) { calls++ })
	if calls == 0 {
		t.Fatalf("progress callback never invoked")
	}
}

// TestZeroWorkFactor checks corner‑case T = 0.
func TestZeroWorkFactor(t *testing.T) {
	puzz, _, err := GeneratePuzzle(0, nil) // No password for test
	if err != nil {
		t.Fatalf("GeneratePuzzle(T=0) failed: %v", err)
	}
	if puzz.Target.Cmp(puzz.G) != 0 {
		t.Fatalf("for T=0 target should equal G")
	}
	if res := SolvePuzzle(puzz, nil); res.Cmp(puzz.G) != 0 {
		t.Fatalf("SolvePuzzle(T=0) wrong: want %s got %s", puzz.G, res)
	}
}
