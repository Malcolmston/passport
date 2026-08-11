package pwhash_test

import (
	"crypto/sha1"
	"encoding/hex"
	"fmt"

	"github.com/malcolmston/passport/pwhash"
)

// ExampleHash shows the two operations a local username/password strategy
// needs: derive a storable hash at registration time, and check a submitted
// password against it at login time. The encoded string is self-describing —
// it carries the algorithm, iteration count and salt — so it is the only thing
// the user table needs to store.
func ExampleHash() {
	// At registration: derive a hash to store in the user record.
	encoded, err := pwhash.Hash("correct horse battery staple")
	if err != nil {
		panic(err)
	}

	// At login: check the submitted password against the stored hash.
	ok, err := pwhash.Verify("correct horse battery staple", encoded)
	fmt.Println("correct password:", ok, err)

	ok, err = pwhash.Verify("hunter2", encoded)
	fmt.Println("wrong password:  ", ok, err)

	// Output:
	// correct password: true <nil>
	// wrong password:   false <nil>
}

// ExampleHashWithParams tunes the derivation cost. Lower iteration counts make
// tests fast; production code should stick to DefaultParams.
func ExampleHashWithParams() {
	encoded, err := pwhash.HashWithParams("s3cret", pwhash.Params{
		Algorithm:  pwhash.SHA512,
		Iterations: 10_000,
		SaltLength: 16,
		KeyLength:  64,
	})
	if err != nil {
		panic(err)
	}

	alg, iterations, salt, dk, err := pwhash.Decode(encoded)
	if err != nil {
		panic(err)
	}
	fmt.Println("algorithm: ", alg)
	fmt.Println("iterations:", iterations)
	fmt.Println("salt bytes:", len(salt))
	fmt.Println("key bytes: ", len(dk))

	// Output:
	// algorithm:  sha512
	// iterations: 10000
	// salt bytes: 16
	// key bytes:  64
}

// ExampleVerify shows that a malformed or tampered encoding is reported as an
// error rather than as a match. Treat any non-nil error as a failed login: a
// credential you cannot parse is a credential you cannot trust.
func ExampleVerify() {
	for _, stored := range []string{
		"not-a-pwhash-string",
		"pbkdf2_md5$1000$c2FsdA$ZGs",        // unsupported algorithm
		"pbkdf2_sha256$600000$c29tZXNhbHQ$", // truncated: empty derived key
	} {
		ok, err := pwhash.Verify("any password at all", stored)
		fmt.Printf("%-38s ok=%v err=%v\n", stored, ok, err)
	}

	// Output:
	// not-a-pwhash-string                    ok=false err=pwhash: malformed encoded hash
	// pbkdf2_md5$1000$c2FsdA$ZGs             ok=false err=pwhash: unknown hash algorithm
	// pbkdf2_sha256$600000$c29tZXNhbHQ$      ok=false err=pwhash: malformed encoded hash
}

// ExampleNeedsRehash shows the credential-upgrade pattern. Right after a
// successful Verify — the one moment the plaintext password is in hand — check
// whether the stored hash predates your current cost settings and, if so,
// re-derive and save it. Over time every active account migrates to the
// stronger parameters without a password reset.
func ExampleNeedsRehash() {
	// A hash stored years ago under much weaker settings.
	legacy, err := pwhash.HashWithParams("s3cret", pwhash.Params{
		Algorithm: pwhash.SHA1, Iterations: 1_000, SaltLength: 8, KeyLength: 20,
	})
	if err != nil {
		panic(err)
	}

	ok, err := pwhash.Verify("s3cret", legacy)
	if err != nil || !ok {
		fmt.Println("login failed")
		return
	}
	fmt.Println("login ok")

	if pwhash.NeedsRehash(legacy, pwhash.DefaultParams()) {
		upgraded, err := pwhash.Hash("s3cret")
		if err != nil {
			panic(err)
		}
		fmt.Println("upgraded:", !pwhash.NeedsRehash(upgraded, pwhash.DefaultParams()))
	}

	// Output:
	// login ok
	// upgraded: true
}

// ExampleKey derives a raw PBKDF2 key. This is the low-level primitive behind
// Hash; reach for it only when you must match an externally defined hash
// format. The vector below is from RFC 6070.
func ExampleKey() {
	dk := pwhash.Key([]byte("password"), []byte("salt"), 2, 20, sha1.New)
	fmt.Println(hex.EncodeToString(dk))
	// Output: ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957
}
