package pwhash

import (
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

// This file pins the pwhash port to the CANONICAL test vectors of the
// specifications it implements. Run with:  go test ./pwhash/... -run Parity
//
// NOTE ON SCOPE: pwhash.go implements only PBKDF2 with an HMAC PRF
// (RFC 2898 / PKCS #5 v2.1, the algorithm behind RFC 6070). It does NOT
// implement scrypt (RFC 7914) or bcrypt. Those KDFs have no code to test in
// this package, so no scrypt/bcrypt vectors are encoded here; see the task
// notes for that gap. RFC 7914 Section 11 additionally publishes
// PBKDF2-HMAC-SHA256 vectors, which DO exercise this port and are included
// below.

// TestParityPBKDF2_SHA1_RFC6070 checks Key against the PBKDF2-HMAC-SHA1
// reference vectors in RFC 6070, "PBKDF2 Test Vectors", Section 2.
// Source: https://www.rfc-editor.org/rfc/rfc6070#section-2
// Cross-checked against golang.org/x/crypto/pbkdf2 pbkdf2_test.go.
func TestParityPBKDF2_SHA1_RFC6070(t *testing.T) {
	tests := []struct {
		password, salt string
		iter, dkLen    int
		want           string
		slow           bool
	}{
		{"password", "salt", 1, 20, "0c60c80f961f0e71f3a9b524af6012062fe037a6", false},
		{"password", "salt", 2, 20, "ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957", false},
		{"password", "salt", 4096, 20, "4b007901b765489abead49d926f721d065a429c1", false},
		// The c=16777216 vector is authoritative but takes many seconds;
		// it is skipped under `go test -short`.
		{"password", "salt", 16777216, 20, "eefe3d61cd4da4e4e9945b3d6ba2158c2634e984", true},
		{"passwordPASSWORDpassword", "saltSALTsaltSALTsaltSALTsaltSALTsalt", 4096, 25, "3d2eec4fe41c849b80c8d83662c0e44a8b291a964cf2f07038", false},
		{"pass\x00word", "sa\x00lt", 4096, 16, "56fa6aa75548099dcc37d7f03425e0c3", false},
	}
	for i, tt := range tests {
		if tt.slow && testing.Short() {
			t.Logf("vector %d (c=%d): skipped in -short mode", i, tt.iter)
			continue
		}
		got := Key([]byte(tt.password), []byte(tt.salt), tt.iter, tt.dkLen, sha1.New)
		if hex.EncodeToString(got) != tt.want {
			t.Errorf("vector %d (c=%d): got %x, want %s", i, tt.iter, got, tt.want)
		}
	}
}

// TestParityPBKDF2_SHA256_RFC7914 checks Key against the PBKDF2-HMAC-SHA256
// reference vectors in RFC 7914, "The scrypt PBKDF", Section 11.
// Source: https://www.rfc-editor.org/rfc/rfc7914#section-11
// The two 64-byte outputs were independently reproduced with
//
//	openssl kdf -keylen 64 -kdfopt digest:SHA2-256 -kdfopt pass:... \
//	  -kdfopt salt:... -kdfopt iter:... PBKDF2
func TestParityPBKDF2_SHA256_RFC7914(t *testing.T) {
	tests := []struct {
		password, salt string
		iter, dkLen    int
		want           string
	}{
		{"passwd", "salt", 1, 64,
			"55ac046e56e3089fec1691c22544b605" +
				"f94185216dde0465e68b9d57c20dacbc" +
				"49ca9cccf179b645991664b39d77ef31" +
				"7c71b845b1e30bd509112041d3a19783"},
		{"Password", "NaCl", 80000, 64,
			"4ddcd8f60b98be21830cee5ef22701f9" +
				"641a4418d04c0414aeff08876b34ab56" +
				"a1d425a1225833549adb841b51c9b317" +
				"6a272bdebba1d078478f62b397f33c8d"},
	}
	for i, tt := range tests {
		got := Key([]byte(tt.password), []byte(tt.salt), tt.iter, tt.dkLen, sha256.New)
		if hex.EncodeToString(got) != tt.want {
			t.Errorf("vector %d (c=%d): got %x, want %s", i, tt.iter, got, tt.want)
		}
	}
}

// TestParityHashVerifyRoundTrip confirms the self-describing Hash/Verify
// wrapper round-trips across every supported PRF: the derived key encoded by
// Hash must verify, and a wrong password must be rejected.
func TestParityHashVerifyRoundTrip(t *testing.T) {
	for _, alg := range []Algorithm{SHA1, SHA256, SHA512} {
		p := Params{Algorithm: alg, Iterations: 1000, SaltLength: 16}
		enc, err := HashWithParams("correct horse battery staple", p)
		if err != nil {
			t.Fatalf("%s: HashWithParams: %v", alg, err)
		}
		ok, err := Verify("correct horse battery staple", enc)
		if err != nil || !ok {
			t.Errorf("%s: Verify(correct) = %v, %v; want true, nil", alg, ok, err)
		}
		bad, err := Verify("Correct Horse Battery Staple", enc)
		if err != nil || bad {
			t.Errorf("%s: Verify(wrong) = %v, %v; want false, nil", alg, bad, err)
		}
	}
}
