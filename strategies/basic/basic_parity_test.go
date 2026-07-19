package basic

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/malcolmston/passport"
)

// Parity tests for the HTTP Basic strategy against the canonical upstream
// vectors from jaredhanson/passport-http.
//
// Source (fetched verbatim):
//
//	https://raw.githubusercontent.com/jaredhanson/passport-http/master/test/strategies/basic-test.js
//	https://raw.githubusercontent.com/jaredhanson/passport-http/master/lib/passport-http/strategies/basic.js
//
// The base64 credential blobs are copied directly from that test file:
//
//	"Ym9iOnNlY3JldA==" -> "bob:secret"  (valid userid + password)
//	"Ym9iOg=="         -> "bob:"        (missing password)
//	"OnNlY3JldA=="     -> ":secret"     (missing username)
//
// Upstream authenticate() outcomes encoded here:
//   - valid "Basic <b64>" with a verified user            -> success(user)
//   - verify returns false                                 -> fail('Basic realm="Users"')
//   - verify returns an error                              -> error(err)
//   - no Authorization header                              -> fail('Basic realm="Users"')
//   - non-Basic scheme ("XXXXX ...")                       -> fail('Basic realm="Users"')
//   - credentials lacking a password ("bob:")              -> fail('Basic realm="Users"') (verify NOT called)
//   - credentials lacking a username (":secret")           -> fail('Basic realm="Users"') (verify NOT called)
//   - capitalized "BASIC" scheme                           -> success(user)
//   - realm option                                         -> fail('Basic realm="Administrators"')
//   - malformed header ("Basic") / bad base64 ("Basic *****") -> fail (upstream sends bare 400).
//
// Note on the two malformed cases: upstream calls fail(400) (a bare 400 with no
// WWW-Authenticate challenge), whereas this Go port documents and implements
// "missing or malformed -> 401 + challenge". The Context type exposes no status
// getter, so only the Fail outcome is asserted here; the 400-vs-401 distinction
// is recorded as a known, intentional divergence, not a bug.

// parityUser mirrors upstream's verify: done(null, {username, password}).
type parityUser struct {
	Username string
	Password string
}

// parityVerify always yields a non-nil user, exactly like the upstream success
// verify. Because it never returns nil, any test whose expected outcome is Fail
// proves the strategy short-circuited before calling verify (e.g. the empty
// username / empty password vectors).
func parityVerify(u, p string) (any, error) {
	return parityUser{Username: u, Password: p}, nil
}

func parityReq(authorization string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	if authorization != "" {
		r.Header.Set("Authorization", authorization)
	}
	return r
}

func parityRun(s *Strategy, r *http.Request) *passport.Context {
	c := &passport.Context{}
	s.Authenticate(c, r)
	return c
}

func TestParityBasicName(t *testing.T) {
	if got := New(parityVerify).Name(); got != "basic" {
		t.Fatalf("Name() = %q, want %q", got, "basic")
	}
}

func TestParityBasicSuccess(t *testing.T) {
	c := parityRun(New(parityVerify), parityReq("Basic Ym9iOnNlY3JldA=="))
	if c.Result() != passport.ResultSuccess {
		t.Fatalf("result = %v, want Success", c.Result())
	}
	u, ok := c.SuccessUser().(parityUser)
	if !ok || u.Username != "bob" || u.Password != "secret" {
		t.Fatalf("user = %#v, want {bob secret}", c.SuccessUser())
	}
}

func TestParityBasicNotVerified(t *testing.T) {
	c := parityRun(New(func(u, p string) (any, error) { return nil, nil }), parityReq("Basic Ym9iOnNlY3JldA=="))
	if c.Result() != passport.ResultFail {
		t.Fatalf("result = %v, want Fail", c.Result())
	}
	if c.Challenge() != `Basic realm="Users"` {
		t.Fatalf("challenge = %q, want %q", c.Challenge(), `Basic realm="Users"`)
	}
}

func TestParityBasicVerifyError(t *testing.T) {
	c := parityRun(New(func(u, p string) (any, error) { return nil, errors.New("something went wrong") }), parityReq("Basic Ym9iOnNlY3JldA=="))
	if c.Result() != passport.ResultError {
		t.Fatalf("result = %v, want Error", c.Result())
	}
	if c.Err() == nil {
		t.Fatal("Err() = nil, want non-nil")
	}
}

func TestParityBasicNoHeader(t *testing.T) {
	c := parityRun(New(parityVerify), parityReq(""))
	if c.Result() != passport.ResultFail {
		t.Fatalf("result = %v, want Fail", c.Result())
	}
	if c.Challenge() != `Basic realm="Users"` {
		t.Fatalf("challenge = %q, want %q", c.Challenge(), `Basic realm="Users"`)
	}
}

func TestParityBasicNonBasicScheme(t *testing.T) {
	c := parityRun(New(parityVerify), parityReq("XXXXX Ym9iOnNlY3JldA=="))
	if c.Result() != passport.ResultFail {
		t.Fatalf("result = %v, want Fail", c.Result())
	}
	if c.Challenge() != `Basic realm="Users"` {
		t.Fatalf("challenge = %q, want %q", c.Challenge(), `Basic realm="Users"`)
	}
}

// "bob:" -- upstream: `if (!userid || !password) return this.fail(challenge)`
// without calling verify. parityVerify would have succeeded if it were called.
func TestParityBasicMissingPassword(t *testing.T) {
	c := parityRun(New(parityVerify), parityReq("Basic Ym9iOg=="))
	if c.Result() != passport.ResultFail {
		t.Fatalf("result = %v, want Fail (verify must not run for empty password)", c.Result())
	}
	if c.Challenge() != `Basic realm="Users"` {
		t.Fatalf("challenge = %q, want %q", c.Challenge(), `Basic realm="Users"`)
	}
}

// ":secret" -- empty username, same short-circuit as above.
func TestParityBasicMissingUsername(t *testing.T) {
	c := parityRun(New(parityVerify), parityReq("Basic OnNlY3JldA=="))
	if c.Result() != passport.ResultFail {
		t.Fatalf("result = %v, want Fail (verify must not run for empty username)", c.Result())
	}
	if c.Challenge() != `Basic realm="Users"` {
		t.Fatalf("challenge = %q, want %q", c.Challenge(), `Basic realm="Users"`)
	}
}

func TestParityBasicCapitalScheme(t *testing.T) {
	c := parityRun(New(parityVerify), parityReq("BASIC Ym9iOnNlY3JldA=="))
	if c.Result() != passport.ResultSuccess {
		t.Fatalf("result = %v, want Success", c.Result())
	}
	u, ok := c.SuccessUser().(parityUser)
	if !ok || u.Username != "bob" || u.Password != "secret" {
		t.Fatalf("user = %#v, want {bob secret}", c.SuccessUser())
	}
}

func TestParityBasicCustomRealm(t *testing.T) {
	s := New(func(u, p string) (any, error) { return nil, nil })
	s.Realm = "Administrators"
	c := parityRun(s, parityReq("Basic Ym9iOnNlY3JldA=="))
	if c.Result() != passport.ResultFail {
		t.Fatalf("result = %v, want Fail", c.Result())
	}
	if c.Challenge() != `Basic realm="Administrators"` {
		t.Fatalf("challenge = %q, want %q", c.Challenge(), `Basic realm="Administrators"`)
	}
}

// Malformed header with no credentials part. Upstream: fail(400). This port
// fails with a challenge instead; only the Fail outcome is asserted.
func TestParityBasicMalformedHeaderNoCreds(t *testing.T) {
	c := parityRun(New(parityVerify), parityReq("Basic"))
	if c.Result() != passport.ResultFail {
		t.Fatalf("result = %v, want Fail", c.Result())
	}
}

// Malformed (non-base64) credentials. Upstream: fail(400). Same note as above.
func TestParityBasicMalformedCredentials(t *testing.T) {
	c := parityRun(New(parityVerify), parityReq("Basic *****"))
	if c.Result() != passport.ResultFail {
		t.Fatalf("result = %v, want Fail", c.Result())
	}
}
