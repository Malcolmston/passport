package anonymous

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/malcolmston/passport"
)

// Parity tests derived from the canonical upstream test vectors in
// jaredhanson/passport-anonymous:
//   https://raw.githubusercontent.com/jaredhanson/passport-anonymous/master/test/strategy.test.js
//
// Upstream behavior encoded here:
//   - the strategy is named "anonymous"
//   - handling a request calls pass() (never success/fail/error/redirect)
//   - the request is left unauthenticated (req.user stays undefined)

// TestParityName mirrors: "should be named anonymous".
func TestParityName(t *testing.T) {
	s := New()
	if got := s.Name(); got != "anonymous" {
		t.Fatalf("Name() = %q, want %q", got, "anonymous")
	}
}

// TestParityHandlingRequestCallsPass mirrors: "should call pass".
func TestParityHandlingRequestCallsPass(t *testing.T) {
	s := New()
	c := &passport.Context{}
	s.Authenticate(c, httptest.NewRequest(http.MethodGet, "/", nil))
	if got := c.Result(); got != passport.ResultPass {
		t.Fatalf("Result() = %v, want %v (ResultPass)", got, passport.ResultPass)
	}
}

// TestParityLeavesUserUndefined mirrors: "should leave req.user undefined".
// The anonymous strategy inspects nothing and stores no user, so no success
// user is recorded and passport.User remains nil.
func TestParityLeavesUserUndefined(t *testing.T) {
	s := New()
	c := &passport.Context{}
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	s.Authenticate(c, r)
	if u := c.SuccessUser(); u != nil {
		t.Fatalf("SuccessUser() = %v, want nil", u)
	}
	if u := passport.User(r); u != nil {
		t.Fatalf("passport.User(r) = %v, want nil", u)
	}
}
