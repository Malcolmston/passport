package basicverify

import (
	"encoding/base64"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/malcolmston/passport"
)

func verify(u, p string) (any, error) {
	if u == "admin" && p == "s3cret" {
		return "admin", nil
	}
	return nil, ErrInvalidCredentials
}

func run(creds string) *passport.Context {
	s := New(Options{Realm: "Test", Verify: verify})
	r := httptest.NewRequest("GET", "/", nil)
	if creds != "" {
		r.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(creds)))
	}
	c := &passport.Context{Writer: httptest.NewRecorder()}
	s.Authenticate(c, r)
	return c
}

func TestValid(t *testing.T) {
	c := run("admin:s3cret")
	if c.Result() != passport.ResultSuccess || c.SuccessUser() != "admin" {
		t.Fatalf("result=%v user=%v", c.Result(), c.SuccessUser())
	}
}

func TestWrongPassword(t *testing.T) {
	c := run("admin:nope")
	if c.Result() != passport.ResultFail {
		t.Fatalf("result=%v", c.Result())
	}
	if !strings.Contains(c.Challenge(), "realm=\"Test\"") {
		t.Fatalf("challenge=%q", c.Challenge())
	}
}

func TestChallengeHeaderSet(t *testing.T) {
	w := httptest.NewRecorder()
	s := New(Options{Realm: "Test", Verify: verify})
	c := &passport.Context{Writer: w}
	s.Authenticate(c, httptest.NewRequest("GET", "/", nil))
	if w.Header().Get("WWW-Authenticate") == "" {
		t.Fatal("expected WWW-Authenticate header")
	}
}

func TestMissing(t *testing.T) {
	c := run("")
	if c.Result() != passport.ResultFail {
		t.Fatalf("result=%v", c.Result())
	}
}

func TestName(t *testing.T) {
	if New(Options{Verify: verify}).Name() != "basic-verify" {
		t.Fatal("name")
	}
}
