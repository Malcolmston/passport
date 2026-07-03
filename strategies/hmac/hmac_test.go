package hmac

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/malcolmston/passport"
)

func sign(secret, body []byte) string {
	m := hmac.New(sha256.New, secret)
	m.Write(body)
	return hex.EncodeToString(m.Sum(nil))
}

func secretFor(id string) []byte {
	if id == "" || id == "client1" {
		return []byte("topsecret")
	}
	return nil
}

func TestValidSignature(t *testing.T) {
	s := New(Options{Secret: secretFor, KeyIDHeader: "X-Key-Id"})
	body := "hello world"
	r := httptest.NewRequest("POST", "/", strings.NewReader(body))
	r.Header.Set("X-Key-Id", "client1")
	r.Header.Set("X-Signature", sign([]byte("topsecret"), []byte(body)))
	c := &passport.Context{}
	s.Authenticate(c, r)
	if c.Result() != passport.ResultSuccess {
		t.Fatalf("result = %v challenge=%q", c.Result(), c.Challenge())
	}
	if c.SuccessUser() != "client1" {
		t.Fatalf("user = %v", c.SuccessUser())
	}
	// Body must be restored for downstream handlers.
	rest, _ := io.ReadAll(r.Body)
	if string(rest) != body {
		t.Fatalf("body not restored: %q", rest)
	}
}

func TestBadSignature(t *testing.T) {
	s := New(Options{Secret: secretFor})
	r := httptest.NewRequest("POST", "/", strings.NewReader("data"))
	r.Header.Set("X-Signature", "deadbeef")
	c := &passport.Context{}
	s.Authenticate(c, r)
	if c.Result() != passport.ResultFail {
		t.Fatalf("result = %v", c.Result())
	}
}

func TestMissingSignature(t *testing.T) {
	s := New(Options{Secret: secretFor})
	c := &passport.Context{}
	s.Authenticate(c, httptest.NewRequest("POST", "/", strings.NewReader("x")))
	if c.Result() != passport.ResultFail {
		t.Fatalf("result = %v", c.Result())
	}
}

func TestUnknownKey(t *testing.T) {
	s := New(Options{Secret: secretFor, KeyIDHeader: "X-Key-Id"})
	r := httptest.NewRequest("POST", "/", strings.NewReader("x"))
	r.Header.Set("X-Key-Id", "nope")
	r.Header.Set("X-Signature", "abc")
	c := &passport.Context{}
	s.Authenticate(c, r)
	if c.Result() != passport.ResultFail {
		t.Fatalf("result = %v", c.Result())
	}
}

func TestDefaultHeader(t *testing.T) {
	if New(Options{Secret: secretFor}).header != "X-Signature" {
		t.Fatal("default header not applied")
	}
}
