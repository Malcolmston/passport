package jwt

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/malcolmston/passport"
)

var secret = []byte("jwt-test-secret")

func verify() VerifyFunc {
	return func(c Claims) (any, error) {
		if c.Subject() == "" {
			return nil, nil
		}
		return "user:" + c.Subject(), nil
	}
}

func bearer(token string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Authorization", "Bearer "+token)
	return r
}

func run(s *Strategy, r *http.Request) *passport.Context {
	c := &passport.Context{}
	s.Authenticate(c, r)
	return c
}

func TestSignAndParseRoundTrip(t *testing.T) {
	tok, err := Sign(secret, Claims{"sub": "abc", "exp": float64(time.Now().Add(time.Hour).Unix())})
	if err != nil {
		t.Fatal(err)
	}
	claims, err := New(secret, nil).Parse(tok)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if claims.Subject() != "abc" {
		t.Errorf("sub = %q", claims.Subject())
	}
}

func TestAuthenticateSuccess(t *testing.T) {
	tok, _ := Sign(secret, Claims{"sub": "42", "exp": float64(time.Now().Add(time.Hour).Unix())})
	c := run(New(secret, verify()), bearer(tok))
	if c.Result() != passport.ResultSuccess || c.SuccessUser() != "user:42" {
		t.Fatalf("result=%v user=%v", c.Result(), c.SuccessUser())
	}
}

func TestAuthenticateMissingToken(t *testing.T) {
	c := run(New(secret, verify()), httptest.NewRequest(http.MethodGet, "/", nil))
	if c.Result() != passport.ResultFail {
		t.Fatalf("result=%v", c.Result())
	}
}

func TestAuthenticateBadSignature(t *testing.T) {
	tok, _ := Sign([]byte("other-secret"), Claims{"sub": "x", "exp": float64(time.Now().Add(time.Hour).Unix())})
	c := run(New(secret, verify()), bearer(tok))
	if c.Result() != passport.ResultFail {
		t.Fatalf("result=%v", c.Result())
	}
}

func TestParseExpired(t *testing.T) {
	tok, _ := Sign(secret, Claims{"sub": "x", "exp": float64(time.Now().Add(-time.Hour).Unix())})
	if _, err := New(secret, nil).Parse(tok); err != ErrExpired {
		t.Fatalf("err = %v, want ErrExpired", err)
	}
}

func TestParseNotYetValid(t *testing.T) {
	tok, _ := Sign(secret, Claims{"sub": "x", "nbf": float64(time.Now().Add(time.Hour).Unix())})
	if _, err := New(secret, nil).Parse(tok); err != ErrNotYet {
		t.Fatalf("err = %v, want ErrNotYet", err)
	}
}

func TestLeewayAllowsSkew(t *testing.T) {
	tok, _ := Sign(secret, Claims{"sub": "x", "exp": float64(time.Now().Add(-30 * time.Second).Unix())})
	s := New(secret, nil)
	s.Leeway = time.Minute
	if _, err := s.Parse(tok); err != nil {
		t.Fatalf("leeway should tolerate 30s skew, got %v", err)
	}
}

func TestParseMalformed(t *testing.T) {
	for _, tok := range []string{"", "a.b", "not-a-jwt", "a.b.c.d"} {
		if _, err := New(secret, nil).Parse(tok); err != ErrMalformed {
			t.Errorf("Parse(%q) err = %v, want ErrMalformed", tok, err)
		}
	}
}

func TestRejectNonHS256(t *testing.T) {
	// A token whose header alg is "none" must be rejected.
	none := encodeSegment([]byte(`{"alg":"none","typ":"JWT"}`)) + "." +
		encodeSegment([]byte(`{"sub":"x"}`)) + "."
	if _, err := New(secret, nil).Parse(none); err != ErrAlgorithm {
		t.Fatalf("err = %v, want ErrAlgorithm", err)
	}
}

func TestAuthenticateNilUserFails(t *testing.T) {
	// Claims with no sub → verify returns nil user → fail.
	tok, _ := Sign(secret, Claims{"exp": float64(time.Now().Add(time.Hour).Unix())})
	c := run(New(secret, verify()), bearer(tok))
	if c.Result() != passport.ResultFail {
		t.Fatalf("result=%v", c.Result())
	}
}

func TestName(t *testing.T) {
	if New(secret, nil).Name() != "jwt" {
		t.Error("unexpected name")
	}
}
