package jwks

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/malcolmston/passport"
)

// TestUnknownKidRefetchIsRateLimited pins the guard against using this server
// as an amplifier: the "kid" in a token header is attacker-controlled and
// unauthenticated, so a stream of tokens carrying made-up kids must not turn
// into a stream of outbound fetches against the provider's JWKS endpoint.
func TestUnknownKidRefetchIsRateLimited(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	var fetches int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&fetches, 1)
		_ = json.NewEncoder(w).Encode(Set{Keys: []JWK{jwkFor("kid-1", key)}})
	}))
	defer srv.Close()

	const budget = 3
	s := New(Options{JWKSURL: srv.URL, MaxRefreshesPerMinute: budget}, nil)

	// 50 requests, each with a kid the key set does not contain.
	for i := 0; i < 50; i++ {
		tok := signRS256(t, key, "attacker-chosen-kid", futureClaims())
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.Header.Set("Authorization", "Bearer "+tok)
		c := &passport.Context{}
		s.Authenticate(c, r)
		if c.Result() != passport.ResultFail {
			t.Fatalf("request %d: unknown kid must not authenticate, got %v", i, c.Result())
		}
	}

	if got := atomic.LoadInt64(&fetches); got > budget {
		t.Errorf("made %d JWKS fetches for 50 unknown-kid requests, want at most %d", got, budget)
	}
	if atomic.LoadInt64(&fetches) == 0 {
		t.Error("expected at least one fetch to populate the cache")
	}
}

// TestRateLimitStillAllowsRotation confirms the budget does not get in the way
// of the legitimate case it exists to permit: a provider rotating its signing
// key mid-flight.
func TestRateLimitStillAllowsRotation(t *testing.T) {
	key1, _ := rsa.GenerateKey(rand.Reader, 2048)
	key2, _ := rsa.GenerateKey(rand.Reader, 2048)
	active := jwkFor("kid-1", key1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(Set{Keys: []JWK{active}})
	}))
	defer srv.Close()

	s := New(Options{JWKSURL: srv.URL}, nil)
	authenticate := func(tok string) passport.Result {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.Header.Set("Authorization", "Bearer "+tok)
		c := &passport.Context{}
		s.Authenticate(c, r)
		return c.Result()
	}

	if got := authenticate(signRS256(t, key1, "kid-1", futureClaims())); got != passport.ResultSuccess {
		t.Fatalf("before rotation: %v", got)
	}
	active = jwkFor("kid-2", key2)
	if got := authenticate(signRS256(t, key2, "kid-2", futureClaims())); got != passport.ResultSuccess {
		t.Fatalf("after rotation: %v", got)
	}
}

// TestECDSASignatureLength pins RFC 7518 Section 3.4: an ES* signature is
// exactly two curve-width integers. A verifier that instead splits whatever
// arrives down the middle would accept alternative framings of a signature.
func TestECDSASignatureLength(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte("a.b"))
	r, sVal, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	good := make([]byte, 64)
	r.FillBytes(good[:32])
	sVal.FillBytes(good[32:])

	if err := verifySignature("ES256", &key.PublicKey, "a.b", good); err != nil {
		t.Fatalf("correctly sized P-256 signature must verify: %v", err)
	}

	for _, tt := range []struct {
		name string
		sig  []byte
	}{
		{"left-padded to 96 bytes", append(make([]byte, 32), good...)},
		{"right-padded to 96 bytes", append(append([]byte{}, good...), make([]byte, 32)...)},
		{"truncated", good[:62]},
		{"empty", nil},
		{"odd length", good[:63]},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if err := verifySignature("ES256", &key.PublicKey, "a.b", tt.sig); err == nil {
				t.Error("a signature that is not exactly 2*32 bytes must be rejected")
			}
		})
	}

	// A P-384 key must not accept a 64-byte (P-256-width) signature.
	k384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifySignature("ES384", &k384.PublicKey, "a.b", good); err == nil {
		t.Error("P-384 must require a 96-byte signature")
	}

	// Guard the nil-curve path rather than letting it panic.
	if err := verifySignature("ES256", &ecdsa.PublicKey{X: big.NewInt(1), Y: big.NewInt(1)}, "a.b", good); err == nil {
		t.Error("a key with no curve must be rejected")
	}
}
