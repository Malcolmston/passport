package basic

import (
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/malcolmston/passport"
)

func verifier() VerifyFunc {
	return func(u, p string) (any, error) {
		switch {
		case u == "alice" && p == "pw":
			return "alice-user", nil
		case u == "boom":
			return nil, errors.New("db error")
		case u == "nil":
			return nil, nil
		default:
			return nil, ErrInvalidCredentials
		}
	}
}

func withBasic(u, p string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	cred := base64.StdEncoding.EncodeToString([]byte(u + ":" + p))
	r.Header.Set("Authorization", "Basic "+cred)
	return r
}

func run(s *Strategy, r *http.Request) *passport.Context {
	c := &passport.Context{}
	s.Authenticate(c, r)
	return c
}

func TestBasicSuccess(t *testing.T) {
	c := run(New(verifier()), withBasic("alice", "pw"))
	if c.Result() != passport.ResultSuccess || c.SuccessUser() != "alice-user" {
		t.Fatalf("result=%v user=%v", c.Result(), c.SuccessUser())
	}
}

func TestBasicNoHeader(t *testing.T) {
	c := run(New(verifier()), httptest.NewRequest(http.MethodGet, "/", nil))
	if c.Result() != passport.ResultFail {
		t.Fatalf("result=%v", c.Result())
	}
	if !strings.HasPrefix(c.Challenge(), "Basic ") {
		t.Errorf("challenge = %q", c.Challenge())
	}
}

func TestBasicWrongPassword(t *testing.T) {
	c := run(New(verifier()), withBasic("alice", "nope"))
	if c.Result() != passport.ResultFail {
		t.Fatalf("result=%v", c.Result())
	}
}

func TestBasicNilUser(t *testing.T) {
	c := run(New(verifier()), withBasic("nil", "x"))
	if c.Result() != passport.ResultFail {
		t.Fatalf("result=%v", c.Result())
	}
}

func TestBasicVerifyError(t *testing.T) {
	c := run(New(verifier()), withBasic("boom", "x"))
	if c.Result() != passport.ResultError {
		t.Fatalf("result=%v", c.Result())
	}
}

func TestBasicMalformedHeaders(t *testing.T) {
	cases := []string{
		"",             // none
		"Bearer abc",   // wrong scheme
		"Basic !!!not", // bad base64
		"Basic " + base64.StdEncoding.EncodeToString([]byte("no-colon")),
	}
	for _, h := range cases {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		if h != "" {
			r.Header.Set("Authorization", h)
		}
		c := run(New(verifier()), r)
		if c.Result() != passport.ResultFail {
			t.Errorf("header %q: result=%v, want Fail", h, c.Result())
		}
	}
}

func TestBasicCustomRealm(t *testing.T) {
	s := New(verifier())
	s.Realm = "Secure"
	c := run(s, httptest.NewRequest(http.MethodGet, "/", nil))
	if !strings.Contains(c.Challenge(), `realm="Secure"`) {
		t.Errorf("challenge = %q", c.Challenge())
	}
}

func TestBasicName(t *testing.T) {
	if New(verifier()).Name() != "basic" {
		t.Error("unexpected name")
	}
}
