package otpauth_test

import (
	"fmt"
	"time"

	"github.com/malcolmston/passport/otpauth"
)

// Example walks a full TOTP enrollment: mint a secret, describe it as an
// otpauth URI for the user's authenticator app, then check the code they type
// back.
func Example() {
	key := otpauth.Key{
		Type:    otpauth.TOTP,
		Issuer:  "Example, Inc.",
		Account: "alice@example.com",
		// In production: otpauth.GenerateSecret(20).
		Secret: "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
	}

	// Render this as a QR code for the authenticator app to scan.
	fmt.Println(key.URL())

	// At sign-in, generate what the app should be showing and compare.
	at := time.Unix(1_000_000_000, 0)
	code, err := key.Code(at)
	if err != nil {
		panic(err)
	}
	_, ok := key.Verify(code, at, 1)
	fmt.Println("accepted:", ok)
	// Output:
	// otpauth://totp/Example,%20Inc.:alice@example.com?algorithm=SHA1&digits=6&issuer=Example%2C%20Inc.&period=30&secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ
	// accepted: true
}

// ExampleKey_Code generates the RFC 6238 Appendix B vector for SHA-512 at
// 8 digits — parameters the fixed-format strategies/totp package cannot express.
func ExampleKey_Code() {
	key := otpauth.Key{
		Type:      otpauth.TOTP,
		Account:   "alice",
		Secret:    "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNA",
		Algorithm: "SHA512",
		Digits:    8,
		Period:    30,
	}
	code, err := key.Code(time.Unix(59, 0))
	if err != nil {
		panic(err)
	}
	fmt.Println(code)
	// Output: 90693936
}

// ExampleKey_Verify shows the asymmetry between the two OTP types. TOTP
// tolerates clock drift in both directions; HOTP only ever looks forward, so a
// counter the server has already consumed can never be replayed.
func ExampleKey_Verify() {
	hotpKey := otpauth.Key{
		Type:    otpauth.HOTP,
		Account: "alice",
		Secret:  "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
		Counter: 5,
	}

	used, _ := hotpKey.CodeAtCounter(4)
	_, ok := hotpKey.Verify(used, time.Time{}, 3)
	fmt.Println("already-consumed counter accepted:", ok)

	ahead, _ := hotpKey.CodeAtCounter(7)
	matched, ok := hotpKey.Verify(ahead, time.Time{}, 3)
	fmt.Println("look-ahead accepted:", ok, "at counter", matched)
	fmt.Println("now persist counter", matched+1)
	// Output:
	// already-consumed counter accepted: false
	// look-ahead accepted: true at counter 7
	// now persist counter 8
}

// ExampleParse reads an otpauth URI produced by another system, applying the
// format's defaults for anything it omits.
func ExampleParse() {
	key, err := otpauth.Parse("otpauth://totp/Example:bob@example.com?secret=GEZDGNBVGY3TQOJQ&issuer=Example")
	if err != nil {
		panic(err)
	}
	fmt.Printf("%s %s/%s alg=%s digits=%d period=%d\n",
		key.Type, key.Issuer, key.Account, key.Algorithm, key.Digits, key.Period)
	// Output: totp Example/bob@example.com alg=SHA1 digits=6 period=30
}
