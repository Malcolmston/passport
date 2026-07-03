package saml

import (
	"encoding/base64"
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
	b64 := base64.StdEncoding.EncodeToString([]byte(samlResponse))
	s := New(Options{})
	r := postForm(url.Values{"SAMLResponse": {b64}})
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
	b64 := base64.StdEncoding.EncodeToString([]byte(samlResponse))
	s := New(Options{Verify: func(nameID string) (any, error) {
		return map[string]string{"email": nameID}, nil
	}})
	r := postForm(url.Values{"SAMLResponse": {b64}})
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
