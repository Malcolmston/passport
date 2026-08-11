// Command jwt_interop is the Go half of the cross-ecosystem JWT check
// described in README.md. Run without arguments it signs an HS256 token for
// Node's jsonwebtoken to verify; run as `jwt_interop verify <token>` it
// verifies a token Node produced.
//
// The compatibility claims this command demonstrates are also asserted
// automatically, against checked-in jsonwebtoken@9 vectors, in
// jwt_interop_test.go — so `go test ./interop` re-checks them without needing
// Node installed.
package main

import (
	"fmt"
	"os"

	"github.com/malcolmston/passport/strategies/jwt"
)

// secret is the shared HMAC key both halves of the interop check use. It is a
// fixed test value, not a credential.
const secret = "shared-secret"

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) > 0 && args[0] == "verify" {
		if len(args) < 2 {
			return fmt.Errorf("usage: %s verify <token>", os.Args[0])
		}
		return verify(args[1])
	}
	if len(args) > 0 {
		return fmt.Errorf("unknown command %q; usage: %s [verify <token>]", args[0], os.Args[0])
	}
	return signToken()
}

// verify parses a token issued elsewhere (Node) and prints its claims.
func verify(token string) error {
	s := jwt.New([]byte(secret), func(c jwt.Claims) (any, error) { return c.Subject(), nil })
	claims, err := s.Parse(token)
	if err != nil {
		return fmt.Errorf("GO_VERIFY_FAIL: %w", err)
	}
	fmt.Printf("GO_VERIFY_OK sub=%v role=%v\n", claims["sub"], claims["role"])
	return nil
}

// signToken issues a token for Node to verify, writing it bare on stdout so it
// can be captured into a shell variable.
func signToken() error {
	tok, err := jwt.Sign([]byte(secret), jwt.Claims{"sub": "user-1", "role": "admin"})
	if err != nil {
		return fmt.Errorf("signing token: %w", err)
	}
	fmt.Print(tok)
	return nil
}
