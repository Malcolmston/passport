package cas

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/malcolmston/passport"
)

const successXML = `<cas:serviceResponse xmlns:cas="http://www.yale.edu/tp/cas">
  <cas:authenticationSuccess>
    <cas:user>jsmith</cas:user>
    <cas:attributes>
      <cas:email>jsmith@example.com</cas:email>
      <cas:displayName>John Smith</cas:displayName>
    </cas:attributes>
  </cas:authenticationSuccess>
</cas:serviceResponse>`

const failureXML = `<cas:serviceResponse xmlns:cas="http://www.yale.edu/tp/cas">
  <cas:authenticationFailure code="INVALID_TICKET">ticket ST-123 not recognized</cas:authenticationFailure>
</cas:serviceResponse>`

func TestRedirectWithoutTicket(t *testing.T) {
	s := New(Config{BaseURL: "https://cas.example.com/cas", Service: "https://app.example/cb"}, nil)
	r := httptest.NewRequest(http.MethodGet, "/login", nil)
	c := &passport.Context{}
	s.Authenticate(c, r)
	if c.Result() != passport.ResultRedirect {
		t.Fatalf("want ResultRedirect, got %v", c.Result())
	}
	want := "https://cas.example.com/cas/login?service=https%3A%2F%2Fapp.example%2Fcb"
	if got := s.LoginURL(); got != want {
		t.Errorf("LoginURL = %q, want %q", got, want)
	}
}

func TestValidateSuccess(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/cas/serviceValidate" {
			t.Errorf("path = %q", r.URL.Path)
		}
		if r.URL.Query().Get("ticket") != "ST-abc" {
			t.Errorf("ticket = %q", r.URL.Query().Get("ticket"))
		}
		w.Header().Set("Content-Type", "application/xml")
		_, _ = w.Write([]byte(successXML))
	}))
	defer srv.Close()

	var gotUser string
	var gotEmail string
	s := New(Config{
		BaseURL:    srv.URL + "/cas",
		Service:    "https://app.example/cb",
		HTTPClient: srv.Client(),
	}, func(username string, attrs map[string]string) (any, error) {
		gotUser = username
		gotEmail = attrs["email"]
		return username, nil
	})

	r := httptest.NewRequest(http.MethodGet, "/cb?ticket=ST-abc", nil)
	c := &passport.Context{}
	s.Authenticate(c, r)

	if c.Result() != passport.ResultSuccess {
		t.Fatalf("want ResultSuccess, got %v (err=%v)", c.Result(), c.Err())
	}
	if gotUser != "jsmith" {
		t.Errorf("user = %q", gotUser)
	}
	if gotEmail != "jsmith@example.com" {
		t.Errorf("email attr = %q", gotEmail)
	}
	if c.SuccessUser() != "jsmith" {
		t.Errorf("SuccessUser = %v", c.SuccessUser())
	}
}

func TestValidateFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(failureXML))
	}))
	defer srv.Close()

	s := New(Config{BaseURL: srv.URL + "/cas", Service: "svc", HTTPClient: srv.Client()}, nil)
	r := httptest.NewRequest(http.MethodGet, "/cb?ticket=bad", nil)
	c := &passport.Context{}
	s.Authenticate(c, r)
	if c.Result() != passport.ResultFail {
		t.Fatalf("want ResultFail, got %v", c.Result())
	}
}
