package pkce

import (
	"strings"
	"testing"
)

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
	if !Verify(MethodPlain, rfcVerifier, rfcVerifier) {
		t.Error("Verify plain should succeed for identical valid verifiers")
	}
	if Verify(Method("bogus"), rfcVerifier, rfcVerifier) {
		t.Error("Verify with unknown method must be false")
	}
}

// TestVerifyRejectsInvalidVerifier pins RFC 7636 Section 4.6: the server must
// validate the code verifier it receives. Under MethodPlain the challenge is
// the verifier, so skipping that check would let a client that presents an
// empty (or trivially short) verifier match an empty stored challenge and
// bypass PKCE altogether.
func TestVerifyRejectsInvalidVerifier(t *testing.T) {
	cases := []struct {
		name              string
		verifier          string
		challenge         string
		method            Method
		reason            string
		alsoRejectedS256T bool
	}{
		{name: "empty verifier and challenge", verifier: "", challenge: "", method: MethodPlain,
			reason: "an empty plain pair must never match"},
		{name: "short verifier", verifier: "abc", challenge: "abc", method: MethodPlain,
			reason: "verifiers below 43 characters carry too little entropy"},
		{name: "over-long verifier", verifier: strings.Repeat("a", 129), challenge: strings.Repeat("a", 129), method: MethodPlain,
			reason: "verifiers above 128 characters are out of range"},
		{name: "illegal character", verifier: strings.Repeat("a", 42) + "/", challenge: strings.Repeat("a", 42) + "/", method: MethodPlain,
			reason: "only the unreserved set is permitted"},
		{name: "empty challenge under S256", verifier: rfcVerifier, challenge: "", method: MethodS256,
			reason: "an absent stored challenge must not verify"},
		{name: "short verifier under S256", verifier: "abc", challenge: S256Challenge("abc"), method: MethodS256,
			reason: "a self-consistent but too-short verifier is still invalid"},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			if Verify(tt.method, tt.verifier, tt.challenge) {
				t.Errorf("Verify(%q, ...) = true, want false: %s", tt.method, tt.reason)
			}
		})
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
