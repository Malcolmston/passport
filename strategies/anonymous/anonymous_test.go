package anonymous

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/malcolmston/passport"
)

func TestAnonymousPasses(t *testing.T) {
	s := New()
	if s.Name() != "anonymous" {
		t.Fatalf("name = %q", s.Name())
	}
	c := &passport.Context{}
	s.Authenticate(c, httptest.NewRequest(http.MethodGet, "/", nil))
	if c.Result() != passport.ResultPass {
		t.Fatalf("want ResultPass, got %v", c.Result())
	}
}
