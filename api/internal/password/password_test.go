package password

import "testing"

func TestHashAndVerifyRoundTrip(t *testing.T) {
	hash, err := Hash("correct-horse-battery-staple")
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}

	match, err := Verify("correct-horse-battery-staple", hash)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !match {
		t.Fatalf("Verify returned false for the correct password")
	}
}

func TestVerifyWrongPasswordFails(t *testing.T) {
	hash, err := Hash("correct-horse-battery-staple")
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}

	match, err := Verify("wrong-password", hash)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if match {
		t.Fatalf("Verify returned true for the wrong password")
	}
}

func TestHashUsesRandomSalt(t *testing.T) {
	h1, err := Hash("same-password")
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}
	h2, err := Hash("same-password")
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}

	if h1 == h2 {
		t.Fatalf("two hashes of the same password were identical (salt not random)")
	}
}

func TestVerifyMalformedHashReturnsError(t *testing.T) {
	if _, err := Verify("anything", "not-a-real-hash"); err == nil {
		t.Fatalf("expected error for malformed hash, got nil")
	}
}

func TestParamsTunedForLowMemoryHost(t *testing.T) {
	const minMemoryKiB = 32 * 1024
	const maxMemoryKiB = 46 * 1024

	if params.Memory < minMemoryKiB || params.Memory > maxMemoryKiB {
		t.Errorf("Memory = %d KiB, want between %d and %d KiB per the 1 GB host caveat", params.Memory, minMemoryKiB, maxMemoryKiB)
	}
	if params.Iterations < 3 || params.Iterations > 4 {
		t.Errorf("Iterations = %d, want 3 or 4 per the 1 GB host caveat", params.Iterations)
	}
	if params.Parallelism != 1 {
		t.Errorf("Parallelism = %d, want 1 per the 1 GB host caveat", params.Parallelism)
	}
}
