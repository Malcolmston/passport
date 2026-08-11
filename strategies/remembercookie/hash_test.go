package remembercookie

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/malcolmston/passport"
)

func authWithCookie(t *testing.T, s *Strategy, value string) *passport.Context {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.AddCookie(&http.Cookie{Name: CookieName, Value: value})
	c := &passport.Context{}
	s.Authenticate(c, r)
	return c
}

// TestHashOptionComparesDigests covers the Options.Hash path, which lets the
// application store only a digest of the validator. A database dump then
// contains nothing that can be replayed as a login.
func TestHashOptionComparesDigests(t *testing.T) {
	const (
		selector  = "sel-1"
		validator = "the-random-validator"
	)
	stored := HashValidator(validator)

	s := New(Options{
		Hash: HashValidator,
		Lookup: func(sel string) (any, string, error) {
			if sel != selector {
				return nil, "", nil
			}
			return "alice", stored, nil
		},
	})

	if c := authWithCookie(t, s, selector+":"+validator); c.Result() != passport.ResultSuccess {
		t.Fatalf("the correct validator must authenticate, got %v (%v)", c.Result(), c.Err())
	}
	// The digest itself, if leaked, must NOT work as a cookie value: that is
	// the whole point of storing a digest rather than the validator.
	if c := authWithCookie(t, s, selector+":"+stored); c.Result() != passport.ResultFail {
		t.Error("a leaked digest was accepted as a validator")
	}
	if c := authWithCookie(t, s, selector+":wrong"); c.Result() != passport.ResultFail {
		t.Error("a wrong validator was accepted")
	}
	if c := authWithCookie(t, s, "unknown-selector:"+validator); c.Result() != passport.ResultFail {
		t.Error("an unknown selector was accepted")
	}
}

// TestWithoutHashComparesRawValue documents the default: the value LookupFunc
// returns is compared as-is, so the store must hold the validator itself.
func TestWithoutHashComparesRawValue(t *testing.T) {
	s := New(Options{
		Lookup: func(string) (any, string, error) { return "alice", "raw-validator", nil },
	})
	if c := authWithCookie(t, s, "sel:raw-validator"); c.Result() != passport.ResultSuccess {
		t.Errorf("Result() = %v, want success", c.Result())
	}
	if c := authWithCookie(t, s, "sel:"+HashValidator("raw-validator")); c.Result() != passport.ResultFail {
		t.Error("without Options.Hash the stored value must be compared verbatim")
	}
}

// TestMalformedCookies covers the edge inputs a public endpoint receives.
func TestMalformedCookies(t *testing.T) {
	s := New(Options{
		Hash:   HashValidator,
		Lookup: func(string) (any, string, error) { return "alice", HashValidator("v"), nil },
	})
	for _, tt := range []struct {
		value string
		want  passport.Result
	}{
		{"no-colon", passport.ResultFail},
		{":v", passport.ResultSuccess}, // empty selector, valid validator
		{"sel:", passport.ResultFail},  // empty validator
		{"sel:v:extra", passport.ResultFail},
	} {
		if c := authWithCookie(t, s, tt.value); c.Result() != tt.want {
			t.Errorf("cookie %q: Result() = %v, want %v", tt.value, c.Result(), tt.want)
		}
	}

	// No cookie at all must Pass, not Fail, so the request continues anonymously.
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	c := &passport.Context{}
	s.Authenticate(c, r)
	if c.Result() != passport.ResultPass {
		t.Errorf("with no cookie Result() = %v, want pass", c.Result())
	}
}

// TestHashValidatorIsStable pins the digest format callers will persist.
func TestHashValidatorIsStable(t *testing.T) {
	got := HashValidator("abc")
	const want = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
	if got != want {
		t.Errorf("HashValidator(\"abc\") = %q, want the SHA-256 of \"abc\" (%q)", got, want)
	}
}
