package bearer

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/malcolmston/passport"
)

// Parity tests for jaredhanson/passport-http-bearer.
//
// Canonical vectors transcribed verbatim from the upstream suite:
//
//	https://raw.githubusercontent.com/jaredhanson/passport-http-bearer/master/test/strategy.test.js
//	https://raw.githubusercontent.com/jaredhanson/passport-http-bearer/master/lib/strategy.js
//
// Fetched 2026-07-19 (master). The canonical token used throughout upstream is
// "mF_9.B5f-4.1JqM" (the RFC 6750 example token). Upstream distinguishes a
// missing-credentials challenge (a WWW-Authenticate string, HTTP 401) from a
// malformed request (this.fail(400), no challenge). The Go passport.Context
// exposes no status accessor, so a 400 is observed here as a ResultFail whose
// Challenge() is empty, versus a challenge fail whose Challenge() carries the
// realm.

const parityToken = "mF_9.B5f-4.1JqM"

func parityVerifier() VerifyFunc {
	return func(token string) (any, error) {
		if token == parityToken {
			return map[string]string{"id": "248289761001"}, nil
		}
		return nil, ErrInvalidToken
	}
}

func parityRun(s *Strategy, mutate func(r *http.Request)) *passport.Context {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	if mutate != nil {
		mutate(r)
	}
	c := &passport.Context{}
	s.Authenticate(c, r)
	return c
}

// --- success vectors ---

func TestParityName(t *testing.T) {
	if got := New(parityVerifier()).Name(); got != "bearer" {
		t.Fatalf("name = %q, want bearer", got)
	}
}

func TestParityHeaderBearerScheme(t *testing.T) {
	c := parityRun(New(parityVerifier()), func(r *http.Request) {
		r.Header.Set("Authorization", "Bearer "+parityToken)
	})
	if c.Result() != passport.ResultSuccess {
		t.Fatalf("result = %v, want success (challenge=%q)", c.Result(), c.Challenge())
	}
	if c.Info() != nil {
		t.Errorf("info = %v, want nil (upstream expects info undefined)", c.Info())
	}
}

func TestParityHeaderCaseInsensitiveScheme(t *testing.T) {
	c := parityRun(New(parityVerifier()), func(r *http.Request) {
		r.Header.Set("Authorization", "bearer "+parityToken)
	})
	if c.Result() != passport.ResultSuccess {
		t.Fatalf("result = %v, want success", c.Result())
	}
}

func TestParityFormBodyParameter(t *testing.T) {
	c := parityRun(New(parityVerifier()), func(r *http.Request) {
		*r = *httptest.NewRequest(http.MethodPost, "/", strings.NewReader("access_token="+parityToken))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	})
	if c.Result() != passport.ResultSuccess {
		t.Fatalf("result = %v, want success", c.Result())
	}
}

func TestParityQueryParameter(t *testing.T) {
	c := parityRun(New(parityVerifier()), func(r *http.Request) {
		*r = *httptest.NewRequest(http.MethodGet, "/?access_token="+parityToken, nil)
	})
	if c.Result() != passport.ResultSuccess {
		t.Fatalf("result = %v, want success", c.Result())
	}
}

// --- challenge vectors ---

func TestParityChallengeWithRealm(t *testing.T) {
	s := New(parityVerifier())
	s.Realm = "example"
	c := parityRun(s, nil)
	if c.Result() != passport.ResultFail {
		t.Fatalf("result = %v, want fail", c.Result())
	}
	if got, want := c.Challenge(), `Bearer realm="example"`; got != want {
		t.Errorf("challenge = %q, want %q", got, want)
	}
}

func TestParityChallengeWithScopeArray(t *testing.T) {
	s := New(parityVerifier())
	s.Scope = []string{"profile", "email"}
	c := parityRun(s, nil)
	if got, want := c.Challenge(), `Bearer realm="Users", scope="profile email"`; got != want {
		t.Errorf("challenge = %q, want %q", got, want)
	}
}

func TestParityChallengeWithScopeString(t *testing.T) {
	s := New(parityVerifier())
	s.Scope = []string{"profile"}
	c := parityRun(s, nil)
	if got, want := c.Challenge(), `Bearer realm="Users", scope="profile"`; got != want {
		t.Errorf("challenge = %q, want %q", got, want)
	}
}

func TestParityChallengeWithoutCredentials(t *testing.T) {
	c := parityRun(New(parityVerifier()), nil)
	if c.Result() != passport.ResultFail {
		t.Fatalf("result = %v, want fail", c.Result())
	}
	if got, want := c.Challenge(), `Bearer realm="Users"`; got != want {
		t.Errorf("challenge = %q, want %q", got, want)
	}
}

func TestParityChallengeNonBearerScheme(t *testing.T) {
	c := parityRun(New(parityVerifier()), func(r *http.Request) {
		r.Header.Set("Authorization", "Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==")
	})
	if got, want := c.Challenge(), `Bearer realm="Users"`; got != want {
		t.Errorf("challenge = %q, want %q", got, want)
	}
}

func TestParityChallengeSchemeSuffix(t *testing.T) {
	c := parityRun(New(parityVerifier()), func(r *http.Request) {
		r.Header.Set("Authorization", "Bearer2 "+parityToken)
	})
	if got, want := c.Challenge(), `Bearer realm="Users"`; got != want {
		t.Errorf("challenge = %q, want %q", got, want)
	}
}

func TestParityChallengeSchemePrefix(t *testing.T) {
	c := parityRun(New(parityVerifier()), func(r *http.Request) {
		r.Header.Set("Authorization", "XBearer "+parityToken)
	})
	if got, want := c.Challenge(), `Bearer realm="Users"`; got != want {
		t.Errorf("challenge = %q, want %q", got, want)
	}
}

// --- malformed request vectors (upstream fail(400): no challenge) ---

func TestParityRefuseBearerWithoutToken(t *testing.T) {
	c := parityRun(New(parityVerifier()), func(r *http.Request) {
		r.Header.Set("Authorization", "Bearer")
	})
	if c.Result() != passport.ResultFail {
		t.Fatalf("result = %v, want fail (400)", c.Result())
	}
	if c.Challenge() != "" {
		t.Errorf("challenge = %q, want empty (upstream fail(400) has no challenge)", c.Challenge())
	}
}

func TestParityRefuseHeaderAndBody(t *testing.T) {
	c := parityRun(New(parityVerifier()), func(r *http.Request) {
		*r = *httptest.NewRequest(http.MethodPost, "/", strings.NewReader("access_token="+parityToken))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.Header.Set("Authorization", "Bearer "+parityToken)
	})
	if c.Result() != passport.ResultFail || c.Challenge() != "" {
		t.Fatalf("result = %v challenge = %q, want fail with empty challenge (400)", c.Result(), c.Challenge())
	}
}

func TestParityRefuseHeaderAndQuery(t *testing.T) {
	c := parityRun(New(parityVerifier()), func(r *http.Request) {
		*r = *httptest.NewRequest(http.MethodGet, "/?access_token="+parityToken, nil)
		r.Header.Set("Authorization", "Bearer "+parityToken)
	})
	if c.Result() != passport.ResultFail || c.Challenge() != "" {
		t.Fatalf("result = %v challenge = %q, want fail with empty challenge (400)", c.Result(), c.Challenge())
	}
}

func TestParityRefuseBodyAndQuery(t *testing.T) {
	c := parityRun(New(parityVerifier()), func(r *http.Request) {
		*r = *httptest.NewRequest(http.MethodPost, "/?access_token="+parityToken, strings.NewReader("access_token="+parityToken))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	})
	if c.Result() != passport.ResultFail || c.Challenge() != "" {
		t.Fatalf("result = %v challenge = %q, want fail with empty challenge (400)", c.Result(), c.Challenge())
	}
}

// --- invalid token & constructor ---

func TestParityInvalidTokenChallenge(t *testing.T) {
	c := parityRun(New(parityVerifier()), func(r *http.Request) {
		r.Header.Set("Authorization", "Bearer wrong-token")
	})
	if c.Result() != passport.ResultFail {
		t.Fatalf("result = %v, want fail", c.Result())
	}
	if got, want := c.Challenge(), `Bearer realm="Users", error="invalid_token"`; got != want {
		t.Errorf("challenge = %q, want %q", got, want)
	}
}

func TestParityConstructorRequiresVerify(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Error("New(nil) did not panic; upstream throws TypeError requiring a verify function")
		}
	}()
	New(nil)
}
