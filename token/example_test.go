package token_test

import (
	"fmt"
	"strings"

	"github.com/malcolmston/passport/token"
)

// Example shows the intended lifecycle of an API token: mint it with
// crypto/rand entropy, hand the caller the token itself, and persist only its
// digest so a leaked database cannot be replayed as a login.
func Example() {
	issued, err := token.New()
	if err != nil {
		panic(err)
	}

	// What goes in the database.
	stored := token.Hash(issued)

	// On a later request, check the presented token against the stored digest.
	fmt.Println("correct token:", token.Verify(issued, stored))
	fmt.Println("wrong token:", token.Verify("some-other-token", stored))
	fmt.Println("digest length:", len(stored))
	// Output:
	// correct token: true
	// wrong token: false
	// digest length: 64
}

// ExampleNumeric mints a short verification code of the kind sent by SMS or
// email. Leading zeros are preserved, so the code always has the requested
// number of digits.
func ExampleNumeric() {
	code, err := token.Numeric(6)
	if err != nil {
		panic(err)
	}
	fmt.Println("length:", len(code))
	fmt.Println("all digits:", strings.IndexFunc(code, func(r rune) bool { return r < '0' || r > '9' }) == -1)
	// Output:
	// length: 6
	// all digits: true
}

// ExampleEqual shows the constant-time comparison to use whenever one side is a
// secret. A plain == would leak how many leading bytes matched through the time
// it takes to return.
func ExampleEqual() {
	fmt.Println(token.Equal("s3cret", "s3cret"))
	fmt.Println(token.Equal("s3cret", "s3crev"))
	// Output:
	// true
	// false
}

// ExampleHex and the other encoders differ only in the alphabet they use; the
// argument is always the number of random bytes, not the string length.
func ExampleHex() {
	hex, err := token.Hex(16)
	if err != nil {
		panic(err)
	}
	urlSafe, err := token.URLSafe(16)
	if err != nil {
		panic(err)
	}
	b32, err := token.Base32(16)
	if err != nil {
		panic(err)
	}
	fmt.Println("hex:", len(hex), "urlsafe:", len(urlSafe), "base32:", len(b32))
	// Output: hex: 32 urlsafe: 22 base32: 26
}
