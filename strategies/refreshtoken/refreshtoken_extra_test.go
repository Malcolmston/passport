package refreshtoken

import (
	"errors"
	"io"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/malcolmston/passport"
)

// errReader always fails on Read, to exercise the body-read error path.
type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, errors.New("boom") }

func TestVerifyGenericError(t *testing.T) {
	boom := errors.New("db down")
	s := New(func(token string) (any, error) { return nil, boom })
	r := httptest.NewRequest("POST", "/token", strings.NewReader("refresh_token=x"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	c := &passport.Context{}
	s.Authenticate(c, r)
	if c.Result() != passport.ResultError {
		t.Fatalf("result=%v, want error", c.Result())
	}
	if c.Err() != boom {
		t.Fatalf("err=%v, want %v", c.Err(), boom)
	}
}

func TestVerifyNilUser(t *testing.T) {
	// verify returns (nil, nil) → treated as failure.
	s := New(func(token string) (any, error) { return nil, nil })
	r := httptest.NewRequest("POST", "/token", strings.NewReader("refresh_token=present"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	c := &passport.Context{}
	s.Authenticate(c, r)
	if c.Result() != passport.ResultFail {
		t.Fatalf("result=%v, want fail", c.Result())
	}
}

func TestNilBody(t *testing.T) {
	s := New(verify)
	r := httptest.NewRequest("POST", "/token", nil)
	r.Body = nil
	c := &passport.Context{}
	s.Authenticate(c, r)
	if c.Result() != passport.ResultFail {
		t.Fatalf("result=%v, want fail (missing token)", c.Result())
	}
}

func TestBodyReadError(t *testing.T) {
	s := New(verify)
	r := httptest.NewRequest("POST", "/token", errReader{})
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	c := &passport.Context{}
	s.Authenticate(c, r)
	if c.Result() != passport.ResultError {
		t.Fatalf("result=%v, want error", c.Result())
	}
}

func TestJSONInvalid(t *testing.T) {
	// Invalid JSON body with a JSON content type yields an empty token → fail.
	s := New(verify)
	r := httptest.NewRequest("POST", "/token", strings.NewReader("{not valid json"))
	r.Header.Set("Content-Type", "application/json")
	c := &passport.Context{}
	s.Authenticate(c, r)
	if c.Result() != passport.ResultFail {
		t.Fatalf("result=%v, want fail", c.Result())
	}
}

func TestJSONBodyRestored(t *testing.T) {
	s := New(verify)
	body := `{"refresh_token":"good"}`
	r := httptest.NewRequest("POST", "/token", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	c := &passport.Context{}
	s.Authenticate(c, r)
	if c.Result() != passport.ResultSuccess {
		t.Fatalf("result=%v", c.Result())
	}
	rest, _ := io.ReadAll(r.Body)
	if string(rest) != body {
		t.Fatalf("body not restored: %q", rest)
	}
}
