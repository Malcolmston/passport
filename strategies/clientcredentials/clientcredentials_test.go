package clientcredentials

import (
	"encoding/base64"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/malcolmston/passport"
)

func verify(id, secret string) (any, error) {
	if id == "app" && secret == "s3cret" {
		return "app", nil
	}
	return nil, ErrInvalidClient
}

func TestBasicAuth(t *testing.T) {
	s := New(verify)
	r := httptest.NewRequest("POST", "/token", nil)
	r.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("app:s3cret")))
	c := &passport.Context{}
	s.Authenticate(c, r)
	if c.Result() != passport.ResultSuccess || c.SuccessUser() != "app" {
		t.Fatalf("result=%v user=%v", c.Result(), c.SuccessUser())
	}
}

func TestFormBody(t *testing.T) {
	s := New(verify)
	body := "client_id=app&client_secret=s3cret"
	r := httptest.NewRequest("POST", "/token", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	c := &passport.Context{}
	s.Authenticate(c, r)
	if c.Result() != passport.ResultSuccess {
		t.Fatalf("result=%v", c.Result())
	}
}

func TestWrongSecret(t *testing.T) {
	s := New(verify)
	r := httptest.NewRequest("POST", "/token", nil)
	r.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("app:nope")))
	c := &passport.Context{}
	s.Authenticate(c, r)
	if c.Result() != passport.ResultFail {
		t.Fatalf("result=%v", c.Result())
	}
}

func TestMissing(t *testing.T) {
	s := New(verify)
	c := &passport.Context{}
	s.Authenticate(c, httptest.NewRequest("POST", "/token", nil))
	if c.Result() != passport.ResultFail {
		t.Fatalf("result=%v", c.Result())
	}
}

func TestName(t *testing.T) {
	if New(verify).Name() != "client-credentials" {
		t.Fatal("name")
	}
}
