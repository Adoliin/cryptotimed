package crypto

import (
	"testing"
)

// TestPasswordIntegratedPuzzle tests that password-based G derivation works correctly
func TestPasswordIntegratedPuzzle(t *testing.T) {
	const squarings = 10 // Keep test quick
	password := []byte("test password 123")

	// Generate puzzle with password
	puzzle1, _, err := GeneratePuzzle(squarings, password)
	if err != nil {
		t.Fatalf("GeneratePuzzle with password failed: %v", err)
	}

	// Verify puzzle has password-related fields set
	if puzzle1.KdfID != 1 { // Argon2id
		t.Errorf("Expected KdfID=1 (Argon2id), got %d", puzzle1.KdfID)
	}
	if puzzle1.Salt == [16]byte{} {
		t.Error("Salt should not be all zeros")
	}

	// Generate another puzzle with same password - should have different salt but same G when derived
	puzzle2, _, err := GeneratePuzzle(squarings, password)
	if err != nil {
		t.Fatalf("Second GeneratePuzzle with password failed: %v", err)
	}

	// Salts should be different (random)
	if puzzle1.Salt == puzzle2.Salt {
		t.Error("Two puzzles with same password should have different salts")
	}

	// But when we derive G from password+salt, we should get the same G for same password+salt
	derivedG1, err := DeriveBaseFromPassword(password, puzzle1.Salt, puzzle1.KdfParams, puzzle1.N)
	if err != nil {
		t.Fatalf("DeriveBaseFromPassword failed: %v", err)
	}
	if derivedG1.Cmp(puzzle1.G) != 0 {
		t.Error("Derived G should match puzzle G")
	}

	// Test with wrong password - should derive different G
	wrongPassword := []byte("wrong password")
	derivedGWrong, err := DeriveBaseFromPassword(wrongPassword, puzzle1.Salt, puzzle1.KdfParams, puzzle1.N)
	if err != nil {
		t.Fatalf("DeriveBaseFromPassword with wrong password failed: %v", err)
	}
	if derivedGWrong.Cmp(puzzle1.G) == 0 {
		t.Error("Wrong password should derive different G")
	}

	// Solve puzzle with correct password-derived G
	target1 := SolvePuzzle(puzzle1, nil)
	if target1.Cmp(puzzle1.Target) != 0 {
		t.Error("SolvePuzzle should produce correct target")
	}

	// Create puzzle with wrong G and solve - should get different target
	puzzleWrongG := puzzle1
	puzzleWrongG.G = derivedGWrong
	targetWrong := SolvePuzzle(puzzleWrongG, nil)
	if targetWrong.Cmp(puzzle1.Target) == 0 {
		t.Error("Wrong G should produce different target")
	}
}

// TestPasswordVsNonPasswordPuzzles tests that password and non-password puzzles work differently
func TestPasswordVsNonPasswordPuzzles(t *testing.T) {
	const squarings = 5

	// Generate puzzle without password (legacy mode)
	puzzleNoPassword, _, err := GeneratePuzzle(squarings, nil)
	if err != nil {
		t.Fatalf("GeneratePuzzle without password failed: %v", err)
	}

	// Generate puzzle with password
	password := []byte("test password")
	puzzleWithPassword, _, err := GeneratePuzzle(squarings, password)
	if err != nil {
		t.Fatalf("GeneratePuzzle with password failed: %v", err)
	}

	// Non-password puzzle should have KdfID = 0
	if puzzleNoPassword.KdfID != 0 {
		t.Errorf("Non-password puzzle should have KdfID=0, got %d", puzzleNoPassword.KdfID)
	}

	// Password puzzle should have KdfID = 1
	if puzzleWithPassword.KdfID != 1 {
		t.Errorf("Password puzzle should have KdfID=1, got %d", puzzleWithPassword.KdfID)
	}

	// Salt should be zero for non-password puzzle
	zeroSalt := [16]byte{}
	if puzzleNoPassword.Salt != zeroSalt {
		t.Error("Non-password puzzle should have zero salt")
	}

	// Salt should be non-zero for password puzzle
	if puzzleWithPassword.Salt == zeroSalt {
		t.Error("Password puzzle should have non-zero salt")
	}

	// Both puzzles should solve correctly
	target1 := SolvePuzzle(puzzleNoPassword, nil)
	if target1.Cmp(puzzleNoPassword.Target) != 0 {
		t.Error("Non-password puzzle should solve correctly")
	}

	target2 := SolvePuzzle(puzzleWithPassword, nil)
	if target2.Cmp(puzzleWithPassword.Target) != 0 {
		t.Error("Password puzzle should solve correctly")
	}
}

// TestKdfParamsEncoding tests that KDF parameters are encoded/decoded correctly
func TestKdfParamsEncoding(t *testing.T) {
	params := Argon2idParams{
		Memory:      65536,
		Time:        4,
		Parallelism: 1,
		KeyLen:      32,
	}

	encoded := EncodeKdfParams(params)
	decoded := DecodeKdfParams(encoded)

	if decoded.Memory != params.Memory {
		t.Errorf("Memory mismatch: got %d, want %d", decoded.Memory, params.Memory)
	}
	if decoded.Time != params.Time {
		t.Errorf("Time mismatch: got %d, want %d", decoded.Time, params.Time)
	}
	if decoded.Parallelism != params.Parallelism {
		t.Errorf("Parallelism mismatch: got %d, want %d", decoded.Parallelism, params.Parallelism)
	}
	if decoded.KeyLen != params.KeyLen {
		t.Errorf("KeyLen mismatch: got %d, want %d", decoded.KeyLen, params.KeyLen)
	}
}

// TestPasswordDeterminism tests that same password+salt always produces same G
func TestPasswordDeterminism(t *testing.T) {
	password := []byte("deterministic test")
	salt := [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	params := DefaultArgon2idParams

	// Generate a test modulus
	puzzle, _, err := GeneratePuzzle(1, nil)
	if err != nil {
		t.Fatalf("Failed to generate test puzzle: %v", err)
	}

	// Derive G multiple times - should always be the same
	g1, err := DeriveBaseFromPassword(password, salt, params, puzzle.N)
	if err != nil {
		t.Fatalf("First derivation failed: %v", err)
	}

	g2, err := DeriveBaseFromPassword(password, salt, params, puzzle.N)
	if err != nil {
		t.Fatalf("Second derivation failed: %v", err)
	}

	g3, err := DeriveBaseFromPassword(password, salt, params, puzzle.N)
	if err != nil {
		t.Fatalf("Third derivation failed: %v", err)
	}

	if g1.Cmp(g2) != 0 || g2.Cmp(g3) != 0 {
		t.Error("Password derivation should be deterministic")
	}

	// Different password should produce different G
	differentPassword := []byte("different password")
	g4, err := DeriveBaseFromPassword(differentPassword, salt, params, puzzle.N)
	if err != nil {
		t.Fatalf("Different password derivation failed: %v", err)
	}

	if g1.Cmp(g4) == 0 {
		t.Error("Different passwords should produce different G values")
	}

	// Different salt should produce different G
	differentSalt := [16]byte{16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1}
	g5, err := DeriveBaseFromPassword(password, differentSalt, params, puzzle.N)
	if err != nil {
		t.Fatalf("Different salt derivation failed: %v", err)
	}

	if g1.Cmp(g5) == 0 {
		t.Error("Different salts should produce different G values")
	}
}