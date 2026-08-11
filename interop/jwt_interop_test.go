package main

import (
	"testing"
	"time"

	"github.com/malcolmston/passport/strategies/jwt"
)

// The tokens below were produced by Node's jsonwebtoken@9 (the reference
// implementation this port claims compatibility with) under the secret
// interopSecret, with {noTimestamp: true} so the encoding is deterministic and
// can be checked into source control. Regenerate them with:
//
//	node -e 'const j=require("jsonwebtoken");console.log(j.sign({sub:"u9"},"shared-secret",{noTimestamp:true}))'
//
// Pinning real vectors turns the compatibility claim in README.md from a
// narrative ("last verified result") into something `go test` re-checks on
// every run, without requiring Node to be installed in CI.
const interopSecret = "shared-secret"

const (
	// {"sub":"user-2","role":"ops"}
	nodeMultiClaim = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyLTIiLCJyb2xlIjoib3BzIn0.qwqDGljwJ-TvdzkV2EujG4cKECyoYHvE6L_zrMo7t7Y"
	// {"sub":"u9"} — single claim, so Go's alphabetical JSON key order cannot
	// diverge from Node's insertion order and the encodings are comparable byte
	// for byte.
	nodeSingleClaim = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1OSJ9.FJf-pQH4DfI8oPpGioW1F_U9vLgvhOeRRH0T-2MdIQE"
	// {"sub":"u3","exp":2101472177} — expires 2036-08-04.
	nodeWithExp = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1MyIsImV4cCI6MjEwMTQ3MjE3N30.KdaxOdXSAmoFihZzUcLWY1aUb-bYcFkDQcSoBSOtKDM"
	// {"sub":"u4","exp":1785892577} — already expired (2026-08-04).
	nodeExpired = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1NCIsImV4cCI6MTc4NTg5MjU3N30.jjfwEzw1vr0bBuPG1VsBqG_dqLisrgTkfsHM-lYWs_Y"
	// {"sub":"u5","nbf":2101472177} — not valid until 2036-08-04.
	nodeNotYet = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1NSIsIm5iZiI6MjEwMTQ3MjE3N30.T2MOgAe50dERGU4V9237d6eNpot_7Ie2-gBVmcLSJP8"
	// {"sub":"u6"} signed with "other-secret".
	nodeWrongSecret = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1NiJ9.q27hjsP_ggct4DcahQUu4U0cQGiSWnfvdRh3KtaulcQ"
	// {"sub":"u7"} signed HS512 — a valid JWT this strategy must still refuse.
	nodeHS512 = "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1NyJ9.MyxCKhXvjqS6yylSwWUjalS0SWSqaQp2Zx7uKYdRci6BNWZJ-tZXW-d9kD27zQegGdm7mi-vyQCSv4qCv3odOA"
	// {"sub":"u8"} with alg "none" and an empty signature.
	nodeAlgNone = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJ1OCJ9."

	// nodeExpTimestamp is the exp/nbf instant baked into the vectors above.
	nodeExpTimestamp = 2101472177
)

func newStrategy() *jwt.Strategy {
	return jwt.New([]byte(interopSecret), func(c jwt.Claims) (any, error) {
		return c.Subject(), nil
	})
}

// TestGoVerifiesNodeToken is the "Node signs -> Go verifies" leg of the
// compatibility claim.
func TestGoVerifiesNodeToken(t *testing.T) {
	claims, err := newStrategy().Parse(nodeMultiClaim)
	if err != nil {
		t.Fatalf("Parse of a jsonwebtoken@9 HS256 token failed: %v", err)
	}
	if got := claims.Subject(); got != "user-2" {
		t.Errorf("sub = %q, want user-2", got)
	}
	if got, _ := claims["role"].(string); got != "ops" {
		t.Errorf("role = %q, want ops", got)
	}
}

// TestGoTokenIsByteIdenticalToNode is the strongest form of the "Go signs ->
// Node verifies" claim: for a single-claim payload, where JSON key ordering
// cannot differ, this port emits exactly the bytes jsonwebtoken emits. If this
// holds, any conforming verifier accepts our tokens.
func TestGoTokenIsByteIdenticalToNode(t *testing.T) {
	got, err := jwt.Sign([]byte(interopSecret), jwt.Claims{"sub": "u9"})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if got != nodeSingleClaim {
		t.Errorf("Go token does not match jsonwebtoken byte for byte:\n go:   %s\n node: %s", got, nodeSingleClaim)
	}
}

// TestGoTokenRoundTripsThroughGo covers the multi-claim case, where Go's
// alphabetical JSON key ordering legitimately differs from Node's insertion
// order. The encodings differ; the semantics must not.
func TestGoTokenRoundTripsThroughGo(t *testing.T) {
	tok, err := jwt.Sign([]byte(interopSecret), jwt.Claims{"sub": "user-1", "role": "admin"})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	claims, err := newStrategy().Parse(tok)
	if err != nil {
		t.Fatalf("Parse of our own token failed: %v", err)
	}
	if claims.Subject() != "user-1" {
		t.Errorf("sub = %q, want user-1", claims.Subject())
	}
	if role, _ := claims["role"].(string); role != "admin" {
		t.Errorf("role = %q, want admin", role)
	}
}

// TestNodeTokensRejected pins the negative half of interoperability: tokens a
// conforming verifier must refuse are refused here too. The alg-confusion cases
// (HS512 and "none") matter most — accepting either would be a signature
// bypass, since "none" carries no signature at all.
func TestNodeTokensRejected(t *testing.T) {
	tests := []struct {
		name  string
		token string
		want  error
	}{
		{"wrong secret", nodeWrongSecret, jwt.ErrSignature},
		{"expired", nodeExpired, jwt.ErrExpired},
		{"different algorithm (HS512)", nodeHS512, jwt.ErrAlgorithm},
		{"alg none", nodeAlgNone, jwt.ErrAlgorithm},
		{"not a jwt", "not.a.jwt", jwt.ErrMalformed},
		{"two segments", "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ4In0", jwt.ErrMalformed},
		{"empty", "", jwt.ErrMalformed},
	}

	s := newStrategy()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := s.Parse(tt.token)
			if err == nil {
				t.Fatalf("Parse accepted a token it must reject")
			}
			if err != tt.want {
				t.Errorf("err = %v, want %v", err, tt.want)
			}
		})
	}
}

// TestNodeTimeClaims checks that exp and nbf produced by jsonwebtoken are
// honoured. The vectors carry an absolute timestamp, so the test reports
// clearly if the fixtures have aged out rather than failing cryptically.
func TestNodeTimeClaims(t *testing.T) {
	if time.Now().Unix() >= nodeExpTimestamp {
		t.Skipf("interop fixtures expired at unix %d; regenerate them with jsonwebtoken", nodeExpTimestamp)
	}

	s := newStrategy()

	claims, err := s.Parse(nodeWithExp)
	if err != nil {
		t.Errorf("token with a future exp was rejected: %v", err)
	} else if claims.Subject() != "u3" {
		t.Errorf("sub = %q, want u3", claims.Subject())
	}

	if _, err := s.Parse(nodeNotYet); err != jwt.ErrNotYet {
		t.Errorf("token with a future nbf: err = %v, want ErrNotYet", err)
	}
}

// TestWrongSecretRejectedBothWays confirms a token we sign is not accepted
// under a different key, the property the README's "wrong-secret token" row
// asserts.
func TestWrongSecretRejectedBothWays(t *testing.T) {
	tok, err := jwt.Sign([]byte("some-other-secret"), jwt.Claims{"sub": "u1"})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if _, err := newStrategy().Parse(tok); err != jwt.ErrSignature {
		t.Errorf("err = %v, want ErrSignature", err)
	}
}
