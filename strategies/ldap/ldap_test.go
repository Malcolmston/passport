package ldap

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/malcolmston/passport"
)

func postForm(vals url.Values) *http.Request {
	r := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(vals.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return r
}

func TestBindSuccessAndDN(t *testing.T) {
	var gotDN, gotPass string
	s := New(Options{
		DNTemplate: "uid=%s,ou=people,dc=example,dc=com",
		Bind: func(dn, password string) (any, error) {
			gotDN, gotPass = dn, password
			return map[string]string{"uid": "alice"}, nil
		},
	})

	r := postForm(url.Values{"username": {"alice"}, "password": {"s3cret"}})
	c := &passport.Context{}
	s.Authenticate(c, r)

	if c.Result() != passport.ResultSuccess {
		t.Fatalf("want ResultSuccess, got %v (err=%v)", c.Result(), c.Err())
	}
	if gotDN != "uid=alice,ou=people,dc=example,dc=com" {
		t.Errorf("dn = %q", gotDN)
	}
	if gotPass != "s3cret" {
		t.Errorf("password = %q", gotPass)
	}
}

func TestBindReject(t *testing.T) {
	s := New(Options{
		Bind: func(dn, password string) (any, error) { return nil, ErrInvalidCredentials },
	})
	r := postForm(url.Values{"username": {"bob"}, "password": {"wrong"}})
	c := &passport.Context{}
	s.Authenticate(c, r)
	if c.Result() != passport.ResultFail {
		t.Fatalf("want ResultFail, got %v", c.Result())
	}
}

func TestMissingCredentials(t *testing.T) {
	s := New(Options{Bind: func(dn, password string) (any, error) { return "u", nil }})
	r := postForm(url.Values{"username": {"bob"}})
	c := &passport.Context{}
	s.Authenticate(c, r)
	if c.Result() != passport.ResultFail {
		t.Fatalf("want ResultFail, got %v", c.Result())
	}
}

func TestCustomFields(t *testing.T) {
	s := New(Options{
		UserField: "u", PassField: "p",
		Bind: func(dn, password string) (any, error) { return dn, nil },
	})
	r := postForm(url.Values{"u": {"carol"}, "p": {"pw"}})
	c := &passport.Context{}
	s.Authenticate(c, r)
	if c.Result() != passport.ResultSuccess || c.SuccessUser() != "carol" {
		t.Fatalf("result=%v user=%v", c.Result(), c.SuccessUser())
	}
}

func TestBindError(t *testing.T) {
	s := New(Options{Bind: func(dn, password string) (any, error) { return nil, http.ErrServerClosed }})
	r := postForm(url.Values{"username": {"x"}, "password": {"y"}})
	c := &passport.Context{}
	s.Authenticate(c, r)
	if c.Result() != passport.ResultError {
		t.Fatalf("want ResultError, got %v", c.Result())
	}
}
