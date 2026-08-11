package pwhash

import (
	"crypto/sha256"
	"errors"
	"strconv"
	"strings"
	"testing"
)

// TestVerifyRejectsEmptyDerivedKey is a regression test for an authentication
// bypass: subtle.ConstantTimeCompare reports two zero-length slices as equal,
// so an encoding whose derived-key segment was empty caused Verify to derive a
// zero-length key and return true for *every* password. Any stored credential
// truncated by a bad migration, a corrupt dump, or a tampering attacker with
// write access to the user table became a skeleton key.
func TestVerifyRejectsEmptyDerivedKey(t *testing.T) {
	const emptyDK = "pbkdf2_sha256$600000$c29tZXNhbHQ$"

	for _, password := range []string{"", "hunter2", "literally-anything"} {
		ok, err := Verify(password, emptyDK)
		if ok {
			t.Errorf("Verify(%q, emptyDK) = true; an empty derived key must never match", password)
		}
		if !errors.Is(err, ErrInvalidHash) {
			t.Errorf("Verify(%q, emptyDK) err = %v, want ErrInvalidHash", password, err)
		}
	}
}

// TestVerifyRejectsEmptySalt guards the sibling case: an unsalted encoding is
// not producible by HashWithParams and signals corruption or tampering.
func TestVerifyRejectsEmptySalt(t *testing.T) {
	ok, err := Verify("hunter2", "pbkdf2_sha256$600000$$ZGVyaXZlZGtleQ")
	if ok {
		t.Error("Verify with empty salt = true, want false")
	}
	if !errors.Is(err, ErrInvalidHash) {
		t.Errorf("err = %v, want ErrInvalidHash", err)
	}
}

func TestDecodeRejectsMalformed(t *testing.T) {
	tests := []struct {
		name    string
		encoded string
		want    error
	}{
		{"empty string", "", ErrInvalidHash},
		{"missing prefix", "sha256$1000$c2FsdA$ZGs", ErrInvalidHash},
		{"too few fields", "pbkdf2_sha256$1000$c2FsdA", ErrInvalidHash},
		{"too many fields", "pbkdf2_sha256$1000$c2FsdA$ZGs$extra", ErrInvalidHash},
		{"unknown algorithm", "pbkdf2_md5$1000$c2FsdA$ZGs", ErrUnknownAlgorithm},
		{"non-numeric iterations", "pbkdf2_sha256$many$c2FsdA$ZGs", ErrInvalidHash},
		{"zero iterations", "pbkdf2_sha256$0$c2FsdA$ZGs", ErrInvalidHash},
		{"negative iterations", "pbkdf2_sha256$-1$c2FsdA$ZGs", ErrInvalidHash},
		{"iterations over cap", "pbkdf2_sha256$100000001$c2FsdA$ZGs", ErrInvalidHash},
		{"bad base64 salt", "pbkdf2_sha256$1000$!!!!$ZGs", ErrInvalidHash},
		{"bad base64 key", "pbkdf2_sha256$1000$c2FsdA$!!!!", ErrInvalidHash},
		{"empty salt", "pbkdf2_sha256$1000$$ZGs", ErrInvalidHash},
		{"empty derived key", "pbkdf2_sha256$1000$c2FsdA$", ErrInvalidHash},
		{"padded base64 rejected", "pbkdf2_sha256$1000$c2FsdA==$ZGs", ErrInvalidHash},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, _, _, err := Decode(tt.encoded)
			if !errors.Is(err, tt.want) {
				t.Errorf("Decode(%q) err = %v, want %v", tt.encoded, err, tt.want)
			}
		})
	}
}

// TestDecodeCapsIterations pins the boundary of the MaxIterations DoS guard.
func TestDecodeCapsIterations(t *testing.T) {
	atCap := "pbkdf2_sha256$" + strconv.Itoa(MaxIterations) + "$c2FsdA$ZGs"
	if _, _, _, _, err := Decode(atCap); err != nil {
		t.Errorf("Decode at MaxIterations err = %v, want nil", err)
	}
	overCap := "pbkdf2_sha256$" + strconv.Itoa(MaxIterations+1) + "$c2FsdA$ZGs"
	if _, _, _, _, err := Decode(overCap); !errors.Is(err, ErrInvalidHash) {
		t.Errorf("Decode above MaxIterations err = %v, want ErrInvalidHash", err)
	}
}

// TestKeyGuardsDegenerateParams pins the non-panicking behaviour of Key for
// out-of-range lengths and iteration counts; before the guard a non-positive
// keyLen sliced past the end of the derived buffer.
func TestKeyGuardsDegenerateParams(t *testing.T) {
	if got := Key([]byte("pw"), []byte("salt"), 10, 0, sha256.New); len(got) != 0 {
		t.Errorf("Key with keyLen=0 returned %d bytes, want 0", len(got))
	}
	if got := Key([]byte("pw"), []byte("salt"), 10, -5, sha256.New); len(got) != 0 {
		t.Errorf("Key with negative keyLen returned %d bytes, want 0", len(got))
	}
	// iter < 1 is clamped to a single iteration, so 0 and 1 agree.
	zero := Key([]byte("pw"), []byte("salt"), 0, 32, sha256.New)
	one := Key([]byte("pw"), []byte("salt"), 1, 32, sha256.New)
	if string(zero) != string(one) {
		t.Error("Key with iter=0 should behave as iter=1")
	}
}

func TestNeedsRehash(t *testing.T) {
	weak, err := HashWithParams("hunter2", Params{Algorithm: SHA1, Iterations: 1000, SaltLength: 8, KeyLength: 20})
	if err != nil {
		t.Fatalf("HashWithParams: %v", err)
	}
	strong, err := HashWithParams("hunter2", DefaultParams())
	if err != nil {
		t.Fatalf("HashWithParams: %v", err)
	}

	tests := []struct {
		name    string
		encoded string
		want    Params
		expect  bool
	}{
		{"weak hash vs defaults", weak, DefaultParams(), true},
		{"current hash vs defaults", strong, DefaultParams(), false},
		{"current hash vs raised iterations", strong, Params{Algorithm: SHA256, Iterations: 1_200_000, SaltLength: 16, KeyLength: 32}, true},
		{"current hash vs longer salt", strong, Params{Algorithm: SHA256, Iterations: 600_000, SaltLength: 32, KeyLength: 32}, true},
		{"current hash vs different algorithm", strong, Params{Algorithm: SHA512, Iterations: 600_000, SaltLength: 16, KeyLength: 32}, true},
		{"malformed always needs rehash", "not-a-hash", DefaultParams(), true},
		{"unknown wanted algorithm", strong, Params{Algorithm: "md5"}, true},
		{"weak hash vs its own params", weak, Params{Algorithm: SHA1, Iterations: 1000, SaltLength: 8, KeyLength: 20}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := NeedsRehash(tt.encoded, tt.want); got != tt.expect {
				t.Errorf("NeedsRehash = %v, want %v", got, tt.expect)
			}
		})
	}
}

// TestHashVerifyRoundTrip covers the happy path across every algorithm plus the
// near-miss passwords that must not verify.
func TestHashVerifyRoundTrip(t *testing.T) {
	for _, alg := range []Algorithm{SHA1, SHA256, SHA512} {
		t.Run(string(alg), func(t *testing.T) {
			p := Params{Algorithm: alg, Iterations: 2000}
			encoded, err := HashWithParams("correct horse", p)
			if err != nil {
				t.Fatalf("HashWithParams: %v", err)
			}
			if !strings.HasPrefix(encoded, "pbkdf2_"+string(alg)+"$") {
				t.Errorf("encoding %q lacks the algorithm prefix", encoded)
			}
			ok, err := Verify("correct horse", encoded)
			if err != nil || !ok {
				t.Errorf("Verify(correct) = %v, %v; want true, nil", ok, err)
			}
			for _, wrong := range []string{"", "correct hors", "correct horse ", "Correct horse"} {
				ok, err := Verify(wrong, encoded)
				if err != nil {
					t.Errorf("Verify(%q) err = %v", wrong, err)
				}
				if ok {
					t.Errorf("Verify(%q) = true, want false", wrong)
				}
			}
		})
	}
}

// TestHashIsSalted confirms two hashes of the same password differ, i.e. the
// salt is actually random per call.
func TestHashIsSalted(t *testing.T) {
	p := Params{Iterations: 1000}
	a, err := HashWithParams("same", p)
	if err != nil {
		t.Fatalf("HashWithParams: %v", err)
	}
	b, err := HashWithParams("same", p)
	if err != nil {
		t.Fatalf("HashWithParams: %v", err)
	}
	if a == b {
		t.Error("two hashes of the same password are identical; the salt is not random")
	}
}

func TestHashWithParamsRejectsUnknownAlgorithm(t *testing.T) {
	if _, err := HashWithParams("pw", Params{Algorithm: "md5"}); !errors.Is(err, ErrUnknownAlgorithm) {
		t.Errorf("err = %v, want ErrUnknownAlgorithm", err)
	}
}

// TestDefaultParamsAreStrong pins the cost floor so a future edit cannot
// quietly weaken every new credential the library issues.
func TestDefaultParamsAreStrong(t *testing.T) {
	p := DefaultParams()
	if p.Iterations < 600_000 {
		t.Errorf("default iterations = %d, want >= 600000 (OWASP guidance for PBKDF2-HMAC-SHA256)", p.Iterations)
	}
	if p.SaltLength < 16 {
		t.Errorf("default salt length = %d, want >= 16", p.SaltLength)
	}
	if p.KeyLength < 32 {
		t.Errorf("default key length = %d, want >= 32", p.KeyLength)
	}
	if p.Algorithm != SHA256 {
		t.Errorf("default algorithm = %q, want sha256", p.Algorithm)
	}
}
