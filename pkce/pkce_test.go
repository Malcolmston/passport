package pkce

import "testing"

// RFC 7636 Appendix B worked example.
const (
	rfcVerifier  = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	rfcChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
)

func TestS256ChallengeRFCVector(t *testing.T) {
	if got := S256Challenge(rfcVerifier); got != rfcChallenge {
		t.Fatalf("S256Challenge = %q, want %q", got, rfcChallenge)
	}
}

func TestComputeChallenge(t *testing.T) {
	tests := []struct {
		method   Method
		verifier string
		want     string
		wantErr  bool
	}{
		{MethodS256, rfcVerifier, rfcChallenge, false},
		{MethodPlain, rfcVerifier, rfcVerifier, false},
		{Method("bogus"), rfcVerifier, "", true},
	}
	for _, tt := range tests {
		got, err := ComputeChallenge(tt.method, tt.verifier)
		if tt.wantErr {
			if err == nil {
				t.Errorf("ComputeChallenge(%q) expected error", tt.method)
			}
			continue
		}
		if err != nil {
			t.Errorf("ComputeChallenge(%q) unexpected error: %v", tt.method, err)
		}
		if got != tt.want {
			t.Errorf("ComputeChallenge(%q) = %q, want %q", tt.method, got, tt.want)
		}
	}
}

func TestVerify(t *testing.T) {
	if !Verify(MethodS256, rfcVerifier, rfcChallenge) {
		t.Error("Verify S256 should succeed for matching pair")
	}
	if Verify(MethodS256, rfcVerifier, "wrong") {
		t.Error("Verify S256 should fail for mismatched challenge")
	}
	if !Verify(MethodPlain, "abc", "abc") {
		t.Error("Verify plain should succeed for identical strings")
	}
	if Verify(Method("bogus"), "a", "a") {
		t.Error("Verify with unknown method must be false")
	}
}

func TestMethod(t *testing.T) {
	if !MethodS256.Valid() || !MethodPlain.Valid() {
		t.Error("S256 and plain must be valid")
	}
	if Method("nope").Valid() {
		t.Error("unknown method must be invalid")
	}
	if MethodS256.String() != "S256" {
		t.Errorf("String() = %q", MethodS256.String())
	}
}

func TestGenerateVerifierAndPair(t *testing.T) {
	v, err := GenerateVerifier()
	if err != nil {
		t.Fatal(err)
	}
	if !ValidVerifier(v) {
		t.Errorf("generated verifier %q is not valid", v)
	}
	if len(v) != 43 {
		t.Errorf("32-byte verifier length = %d, want 43", len(v))
	}
	p, err := New()
	if err != nil {
		t.Fatal(err)
	}
	if !Verify(p.Method, p.Verifier, p.Challenge) {
		t.Error("New() pair must verify")
	}
	ap := p.AuthParams()
	if ap["code_challenge"] != p.Challenge || ap["code_challenge_method"] != "S256" {
		t.Errorf("AuthParams = %v", ap)
	}
}

func TestVerifierWithLengthBounds(t *testing.T) {
	if _, err := VerifierWithLength(16); err == nil {
		t.Error("length below minimum must error")
	}
	if _, err := VerifierWithLength(200); err == nil {
		t.Error("length above maximum must error")
	}
	v, err := VerifierWithLength(96)
	if err != nil {
		t.Fatal(err)
	}
	if !ValidVerifier(v) {
		t.Errorf("96-byte verifier %q invalid (len %d)", v, len(v))
	}
}

func TestValidVerifier(t *testing.T) {
	if ValidVerifier("tooshort") {
		t.Error("short verifier must be invalid")
	}
	bad := make([]byte, 43)
	for i := range bad {
		bad[i] = '!'
	}
	if ValidVerifier(string(bad)) {
		t.Error("illegal characters must be invalid")
	}
}

func BenchmarkS256Challenge(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = S256Challenge(rfcVerifier)
	}
}
