package pkce_test

import (
	"fmt"

	"github.com/malcolmston/passport/pkce"
)

// Example shows the two halves of a PKCE-protected authorization-code flow: the
// client derives a challenge before redirecting, keeps the verifier locally,
// and presents it on the back-channel token request.
func Example() {
	// Before redirecting the user agent to the provider.
	pair, err := pkce.New()
	if err != nil {
		panic(err)
	}

	// These go on the front-channel authorization request.
	auth := pair.AuthParams()
	fmt.Println("method:", auth["code_challenge_method"])

	// The verifier stays with the client and travels only on the token POST.
	fmt.Println("token request carries:", len(pair.TokenParams()), "parameter")

	// What the authorization server does when the code is redeemed.
	fmt.Println("verified:", pkce.Verify(pair.Method, pair.Verifier, pair.Challenge))
	// Output:
	// method: S256
	// token request carries: 1 parameter
	// verified: true
}

// ExampleS256Challenge reproduces the worked example from RFC 7636 Appendix B.
func ExampleS256Challenge() {
	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	fmt.Println(pkce.S256Challenge(verifier))
	// Output: E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM
}

// ExampleVerify shows that verification fails closed for a verifier that does
// not meet RFC 7636's syntax rules, which is what stops an empty verifier from
// "matching" an empty plain challenge.
func ExampleVerify() {
	good := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"

	fmt.Println(pkce.Verify(pkce.MethodS256, good, pkce.S256Challenge(good)))
	fmt.Println(pkce.Verify(pkce.MethodPlain, good, good))
	fmt.Println(pkce.Verify(pkce.MethodPlain, "", ""))
	fmt.Println(pkce.Verify(pkce.MethodS256, good, "not-the-challenge"))
	// Output:
	// true
	// true
	// false
	// false
}

// ExampleParseMethod shows RFC 7636's default: an absent code_challenge_method
// means "plain".
func ExampleParseMethod() {
	for _, raw := range []string{"S256", "plain", ""} {
		m, err := pkce.ParseMethod(raw)
		fmt.Printf("%q -> %v (err %v)\n", raw, m, err)
	}
	if _, err := pkce.ParseMethod("S512"); err != nil {
		fmt.Println("S512 rejected")
	}
	// Output:
	// "S256" -> S256 (err <nil>)
	// "plain" -> plain (err <nil>)
	// "" -> plain (err <nil>)
	// S512 rejected
}
