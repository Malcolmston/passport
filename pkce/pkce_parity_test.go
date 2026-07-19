package pkce

// Parity tests against the CANONICAL test vectors of RFC 7636 (Proof Key for
// Code Exchange). Vectors are transcribed directly from the RFC text, which is
// authoritative for these famous fixed values.
//
// Primary source: https://www.rfc-editor.org/rfc/rfc7636
//   - Appendix A: "Notes on Implementing Base64url Encoding without Padding"
//   - Appendix B: "Example for the S256 code_challenge_method"
// Verifier syntax (charset / length 43..128) is defined in Section 4.1.

import (
	"encoding/base64"
	"testing"
)

// rawURLEncodeForParity mirrors the base64url-without-padding encoding the pkce
// package uses internally (base64.RawURLEncoding), so parity tests can assert
// the RFC's octet->string examples directly.
func rawURLEncodeForParity(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

// --- RFC 7636 Appendix A -----------------------------------------------------
// "Notes on Implementing Base64url Encoding without Padding".
// The RFC gives a worked example: the octet sequence [3, 236, 255, 224, 193]
// base64url-encodes (no padding) to "A-z_4ME".
// Source: https://www.rfc-editor.org/rfc/rfc7636#appendix-A
func TestParityAppendixABase64url(t *testing.T) {
	// The package does not export a raw base64url helper, but S256Challenge and
	// the verifier encoding both rely on base64.RawURLEncoding. We assert the
	// exact RFC example through the standard encoding the package uses.
	got := rawURLEncodeForParity([]byte{3, 236, 255, 224, 193})
	const want = "A-z_4ME"
	if got != want {
		t.Fatalf("Appendix A base64url = %q, want %q", got, want)
	}
}

// --- RFC 7636 Appendix B -----------------------------------------------------
// The 32-octet random sequence and its derived code_verifier / code_challenge.
// Source: https://www.rfc-editor.org/rfc/rfc7636#appendix-B
var parityAppendixBVerifierOctets = []byte{
	116, 24, 223, 180, 151, 153, 224, 37, 79, 250, 96, 125, 216, 173,
	187, 186, 22, 212, 37, 77, 105, 214, 191, 240, 91, 88, 5, 88, 83,
	132, 141, 121,
}

// SHA256(ASCII(code_verifier)) octets, per Appendix B.
var parityAppendixBChallengeOctets = []byte{
	19, 211, 30, 150, 26, 26, 216, 236, 47, 22, 177, 12, 76, 152, 46,
	8, 118, 168, 120, 173, 109, 241, 68, 86, 110, 225, 137, 74, 203,
	112, 249, 195,
}

const (
	parityVerifier  = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	parityChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
)

// The random octets base64url-encode to the canonical code_verifier string.
func TestParityAppendixBVerifierEncoding(t *testing.T) {
	if got := rawURLEncodeForParity(parityAppendixBVerifierOctets); got != parityVerifier {
		t.Fatalf("Appendix B verifier encoding = %q, want %q", got, parityVerifier)
	}
	if !ValidVerifier(parityVerifier) {
		t.Errorf("canonical verifier %q must pass ValidVerifier", parityVerifier)
	}
	if len(parityVerifier) != 43 {
		t.Errorf("canonical verifier length = %d, want 43", len(parityVerifier))
	}
}

// The published SHA256 octets base64url-encode to the canonical code_challenge.
func TestParityAppendixBChallengeEncoding(t *testing.T) {
	if got := rawURLEncodeForParity(parityAppendixBChallengeOctets); got != parityChallenge {
		t.Fatalf("Appendix B challenge encoding = %q, want %q", got, parityChallenge)
	}
}

// S256Challenge(verifier) reproduces the Appendix B code_challenge end to end.
func TestParityS256Challenge(t *testing.T) {
	if got := S256Challenge(parityVerifier); got != parityChallenge {
		t.Fatalf("S256Challenge(%q) = %q, want %q", parityVerifier, got, parityChallenge)
	}
	got, err := ComputeChallenge(MethodS256, parityVerifier)
	if err != nil {
		t.Fatalf("ComputeChallenge S256 error: %v", err)
	}
	if got != parityChallenge {
		t.Fatalf("ComputeChallenge S256 = %q, want %q", got, parityChallenge)
	}
	if !Verify(MethodS256, parityVerifier, parityChallenge) {
		t.Error("Verify must accept the canonical S256 verifier/challenge pair")
	}
}

// --- RFC 7636 Section 4.2 ----------------------------------------------------
// "plain" transform: code_challenge = code_verifier (identity).
// Source: https://www.rfc-editor.org/rfc/rfc7636#section-4.2
func TestParityPlainTransform(t *testing.T) {
	if got := PlainChallenge(parityVerifier); got != parityVerifier {
		t.Fatalf("PlainChallenge = %q, want identity %q", got, parityVerifier)
	}
	got, err := ComputeChallenge(MethodPlain, parityVerifier)
	if err != nil {
		t.Fatalf("ComputeChallenge plain error: %v", err)
	}
	if got != parityVerifier {
		t.Fatalf("ComputeChallenge plain = %q, want %q", got, parityVerifier)
	}
	if !Verify(MethodPlain, parityVerifier, parityVerifier) {
		t.Error("Verify must accept identical strings under plain")
	}
	if Verify(MethodPlain, parityVerifier, parityChallenge) {
		t.Error("Verify plain must reject non-identical challenge")
	}
}

// --- RFC 7636 Section 4.1 ----------------------------------------------------
// code_verifier = high-entropy string using unreserved characters
// [A-Z] / [a-z] / [0-9] / "-" / "." / "_" / "~", with a minimum length of 43
// characters and a maximum length of 128 characters.
// Source: https://www.rfc-editor.org/rfc/rfc7636#section-4.1
func TestParityVerifierLengthBounds(t *testing.T) {
	// ABNF unreserved characters are all legal; build strings of legal chars at
	// boundary lengths so only the length under test decides validity.
	mk := func(n int) string {
		b := make([]byte, n)
		for i := range b {
			b[i] = 'a'
		}
		return string(b)
	}
	cases := []struct {
		n    int
		want bool
	}{
		{42, false},  // one below minimum
		{43, true},   // minimum
		{128, true},  // maximum
		{129, false}, // one above maximum
	}
	for _, c := range cases {
		if got := ValidVerifier(mk(c.n)); got != c.want {
			t.Errorf("ValidVerifier(len=%d) = %v, want %v", c.n, got, c.want)
		}
	}
}

// Every unreserved character is accepted; a reserved character is rejected.
func TestParityVerifierCharset(t *testing.T) {
	// A 43-char verifier exercising all four unreserved classes plus the four
	// unreserved punctuation marks.
	const legal = "ABCDEFGHIJKLMNOPabcdefghijklmnop0123456789-._~"
	if len(legal) < 43 {
		t.Fatalf("legal sample too short: %d", len(legal))
	}
	if !ValidVerifier(legal) {
		t.Errorf("verifier of unreserved chars %q must be valid", legal)
	}
	// Characters outside the unreserved set must be rejected. These are all
	// reserved / disallowed per RFC 3986 unreserved set.
	for _, bad := range []byte{'!', '+', '/', '=', ' ', '%', ':', '@'} {
		v := "ABCDEFGHIJKLMNOPabcdefghijklmnop0123456789-._" + string(bad)
		if len(v) < 43 {
			v += "aaaaa"
		}
		if ValidVerifier(v) {
			t.Errorf("verifier containing reserved byte %q must be invalid", bad)
		}
	}
}

// Unknown transform methods must be rejected (RFC 7636 defines exactly two).
func TestParityUnknownMethod(t *testing.T) {
	if Method("S128").Valid() || Method("").Valid() || Method("sha256").Valid() {
		t.Error("only S256 and plain are valid PKCE methods")
	}
	if _, err := ComputeChallenge(Method("S128"), parityVerifier); err == nil {
		t.Error("ComputeChallenge with unknown method must error")
	}
	if Verify(Method("S128"), parityVerifier, parityChallenge) {
		t.Error("Verify with unknown method must be false")
	}
}
