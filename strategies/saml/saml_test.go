package saml

import (
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/malcolmston/passport"
)

const samlResponse = `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
  <saml:Assertion>
    <saml:Subject>
      <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">alice@example.com</saml:NameID>
    </saml:Subject>
  </saml:Assertion>
</samlp:Response>`

func postForm(vals url.Values) *http.Request {
	r := httptest.NewRequest(http.MethodPost, "/acs", strings.NewReader(vals.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return r
}

func TestExtractNameID(t *testing.T) {
	b64 := base64.StdEncoding.EncodeToString([]byte(samlResponse))
	got, err := ExtractNameID(b64)
	if err != nil {
		t.Fatalf("ExtractNameID: %v", err)
	}
	if got != "alice@example.com" {
		t.Errorf("NameID = %q", got)
	}
}

func TestAuthenticateSuccess(t *testing.T) {
	f := newFixture(newTestIdP(t, "rsa"))
	s := f.strategy()
	r := postForm(url.Values{"SAMLResponse": {f.encode(t)}})
	c := &passport.Context{}
	s.Authenticate(c, r)

	if c.Result() != passport.ResultSuccess {
		t.Fatalf("want ResultSuccess, got %v", c.Result())
	}
	if c.SuccessUser() != "alice@example.com" {
		t.Errorf("SuccessUser = %v", c.SuccessUser())
	}
}

func TestAuthenticateWithVerify(t *testing.T) {
	f := newFixture(newTestIdP(t, "rsa"))
	s := f.strategy(func(o *Options) {
		o.Verify = func(nameID string) (any, error) {
			return map[string]string{"email": nameID}, nil
		}
	})
	r := postForm(url.Values{"SAMLResponse": {f.encode(t)}})
	c := &passport.Context{}
	s.Authenticate(c, r)
	if c.Result() != passport.ResultSuccess {
		t.Fatalf("want ResultSuccess, got %v", c.Result())
	}
	u := c.SuccessUser().(map[string]string)
	if u["email"] != "alice@example.com" {
		t.Errorf("user = %v", u)
	}
}

// TestAuthenticateRejectsUnsignedResponse is the regression for the package's
// original behaviour, which authenticated whatever NameID it found in an
// unsigned, unvalidated document. The literal samlResponse constant above is
// exactly what used to be accepted.
func TestAuthenticateRejectsUnsignedResponse(t *testing.T) {
	f := newFixture(newTestIdP(t, "rsa"))
	b64 := base64.StdEncoding.EncodeToString([]byte(samlResponse))
	c := &passport.Context{}
	f.strategy().Authenticate(c, postForm(url.Values{"SAMLResponse": {b64}}))
	if c.Result() != passport.ResultFail {
		t.Fatalf("want ResultFail for an unsigned response, got %v (user %v)", c.Result(), c.SuccessUser())
	}
}

// TestAuthenticateVerifyErrors distinguishes a rejected login from an internal
// error.
func TestAuthenticateVerifyErrors(t *testing.T) {
	t.Run("nil user fails", func(t *testing.T) {
		f := newFixture(newTestIdP(t, "rsa"))
		s := f.strategy(func(o *Options) {
			o.Verify = func(string) (any, error) { return nil, nil }
		})
		c := &passport.Context{}
		s.Authenticate(c, postForm(url.Values{"SAMLResponse": {f.encode(t)}}))
		if c.Result() != passport.ResultFail {
			t.Fatalf("want ResultFail, got %v", c.Result())
		}
	})
	t.Run("error is an internal error", func(t *testing.T) {
		f := newFixture(newTestIdP(t, "rsa"))
		boom := errors.New("boom")
		s := f.strategy(func(o *Options) {
			o.Verify = func(string) (any, error) { return nil, boom }
		})
		c := &passport.Context{}
		s.Authenticate(c, postForm(url.Values{"SAMLResponse": {f.encode(t)}}))
		if c.Result() != passport.ResultError || !errors.Is(c.Err(), boom) {
			t.Fatalf("result = %v, err = %v", c.Result(), c.Err())
		}
	})
}

func TestBadBase64(t *testing.T) {
	s := New(Options{})
	r := postForm(url.Values{"SAMLResponse": {"!!!not base64!!!"}})
	c := &passport.Context{}
	s.Authenticate(c, r)
	if c.Result() != passport.ResultFail {
		t.Fatalf("want ResultFail, got %v", c.Result())
	}
}

func TestMissing(t *testing.T) {
	s := New(Options{})
	r := postForm(url.Values{})
	c := &passport.Context{}
	s.Authenticate(c, r)
	if c.Result() != passport.ResultFail {
		t.Fatalf("want ResultFail, got %v", c.Result())
	}
}
