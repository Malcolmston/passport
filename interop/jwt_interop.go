package main

import (
	"fmt"
	"github.com/malcolmston/passport/strategies/jwt"
	"os"
)

func main() {
	secret := []byte("shared-secret")
	if len(os.Args) > 1 && os.Args[1] == "verify" {
		// verify a token passed on argv from Node
		s := jwt.New(secret, func(c jwt.Claims) (any, error) { return c.Subject(), nil })
		claims, err := s.Parse(os.Args[2])
		if err != nil {
			fmt.Println("GO_VERIFY_FAIL:", err)
			os.Exit(1)
		}
		fmt.Printf("GO_VERIFY_OK sub=%v role=%v\n", claims["sub"], claims["role"])
		return
	}
	// sign a token for Node to verify
	tok, _ := jwt.Sign(secret, jwt.Claims{"sub": "user-1", "role": "admin"})
	fmt.Print(tok)
}
