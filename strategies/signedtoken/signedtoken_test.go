package signedtoken

import (
	"net/http/httptest"
	"testing"
	"time"

	"github.com/malcolmston/passport"
)

var secret = []byte("sign-secret")

func fixed(unix int64) func() time.Time {
	return func() time.Time { return time.Unix(unix, 0) }
}

func run(token string, now func() time.Time) *passport.Context {
	s := New(Options{Secret: secret, Now: now})
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Authorization", "Bearer "+token)
	c := &passport.Context{}
	s.Authenticate(c, r)
	return c
}

func TestValid(t *testing.T) {
	token, err := Sign(secret, map[string]any{"sub": "alice", "role": "admin"})
	if err != nil {
		t.Fatal(err)
	}
	c := run(token, fixed(0))
	if c.Result() != passport.ResultSuccess {
		t.Fatalf("result=%v", c.Result())
	}
	claims, ok := c.SuccessUser().(map[string]any)
	if !ok || claims["sub"] != "alice" {
		t.Fatalf("claims=%v", c.SuccessUser())
	}
}

func TestExpired(t *testing.T) {
	token, _ := Sign(secret, map[string]any{"sub": "alice", "exp": float64(1000)})
	c := run(token, fixed(2000))
	if c.Result() != passport.ResultFail || c.Challenge() != "Token expired" {
		t.Fatalf("result=%v challenge=%q", c.Result(), c.Challenge())
	}
}

func TestNotYetExpired(t *testing.T) {
	token, _ := Sign(secret, map[string]any{"sub": "alice", "exp": float64(1000)})
	c := run(token, fixed(500))
	if c.Result() != passport.ResultSuccess {
		t.Fatalf("result=%v", c.Result())
	}
}

func TestTampered(t *testing.T) {
	token, _ := Sign(secret, map[string]any{"sub": "alice"})
	c := run(token+"ff", fixed(0))
	if c.Result() != passport.ResultFail {
		t.Fatalf("result=%v", c.Result())
	}
}

func TestWrongSecret(t *testing.T) {
	token, _ := Sign([]byte("other"), map[string]any{"sub": "alice"})
	c := run(token, fixed(0))
	if c.Result() != passport.ResultFail {
		t.Fatalf("result=%v", c.Result())
	}
}

func TestMissing(t *testing.T) {
	s := New(Options{Secret: secret})
	c := &passport.Context{}
	s.Authenticate(c, httptest.NewRequest("GET", "/", nil))
	if c.Result() != passport.ResultFail {
		t.Fatalf("result=%v", c.Result())
	}
}

func TestName(t *testing.T) {
	if New(Options{Secret: secret}).Name() != "signed-token" {
		t.Fatal("name")
	}
}
