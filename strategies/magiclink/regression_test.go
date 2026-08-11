package magiclink

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/malcolmston/passport"
)

func authenticate(t *testing.T, s *Strategy, token string) *passport.Context {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, "/verify?token="+url.QueryEscape(token), nil)
	c := &passport.Context{}
	s.Authenticate(c, r)
	return c
}

// TestAddressContainingPipeRoundTrips pins a decoding bug: the payload is
// "email|expiry", and splitting it at the FIRST "|" mis-assigns the fields when
// the address itself contains one (RFC 5321 permits it in a quoted local part).
// Such a token was minted by this very package yet rejected on presentation.
func TestAddressContainingPipeRoundTrips(t *testing.T) {
	secret := []byte("magic-secret")
	exp := time.Now().Add(15 * time.Minute)
	s := New(Options{Secret: secret})

	for _, email := range []string{
		"alice@example.com",
		`"weird|local"@example.com`,
		`"a|b|c"@example.com`,
		"trailing|@example.com",
	} {
		t.Run(email, func(t *testing.T) {
			c := authenticate(t, s, Sign(secret, email, exp))
			if c.Result() != passport.ResultSuccess {
				t.Fatalf("Result() = %v (%v)", c.Result(), c.Err())
			}
			if got, _ := c.SuccessUser().(string); got != email {
				t.Errorf("authenticated user = %q, want %q", got, email)
			}
		})
	}
}

// TestEmptyEmailRejected makes sure a payload of just "|<exp>" cannot
// authenticate an empty identity.
func TestEmptyEmailRejected(t *testing.T) {
	secret := []byte("magic-secret")
	s := New(Options{Secret: secret})
	if c := authenticate(t, s, Sign(secret, "", time.Now().Add(time.Hour))); c.Result() != passport.ResultFail {
		t.Errorf("Result() = %v, want fail for an empty address", c.Result())
	}
}

// TestSignatureEncodingIsRobust covers the switch from comparing hex strings to
// comparing decoded bytes: case must not matter, and a non-hex signature must
// be rejected rather than reaching the comparison.
func TestSignatureEncodingIsRobust(t *testing.T) {
	secret := []byte("magic-secret")
	s := New(Options{Secret: secret})
	tok := Sign(secret, "alice@example.com", time.Now().Add(time.Hour))
	dot := strings.LastIndexByte(tok, '.')
	body, sig := tok[:dot], tok[dot+1:]

	if c := authenticate(t, s, body+"."+strings.ToUpper(sig)); c.Result() != passport.ResultSuccess {
		t.Errorf("an upper-case hex signature must be accepted, got %v", c.Result())
	}
	for _, bad := range []string{"", "zz", "not-hex-at-all", sig[:len(sig)-1], sig + "00"} {
		if c := authenticate(t, s, body+"."+bad); c.Result() != passport.ResultFail {
			t.Errorf("signature %q must be rejected, got %v", bad, c.Result())
		}
	}
}

// TestTamperingAndExpiry covers the two properties the package promises.
func TestTamperingAndExpiry(t *testing.T) {
	secret := []byte("magic-secret")
	now := time.Unix(1_700_000_000, 0)
	s := New(Options{Secret: secret, Now: func() time.Time { return now }})

	valid := Sign(secret, "alice@example.com", now.Add(time.Hour))
	if c := authenticate(t, s, valid); c.Result() != passport.ResultSuccess {
		t.Fatalf("valid token rejected: %v", c.Err())
	}

	// A token signed with a different key must not verify.
	forged := Sign([]byte("other-secret"), "attacker@example.com", now.Add(time.Hour))
	if c := authenticate(t, s, forged); c.Result() != passport.ResultFail {
		t.Error("a token signed with the wrong key was accepted")
	}

	// An expired token must not verify.
	expired := Sign(secret, "alice@example.com", now.Add(-time.Second))
	if c := authenticate(t, s, expired); c.Result() != passport.ResultFail {
		t.Error("an expired token was accepted")
	}

	// Structurally broken tokens must fail rather than panic.
	for _, bad := range []string{"", "no-dot", ".", "!!!.aabb", "aGk.zz"} {
		if c := authenticate(t, s, bad); c.Result() != passport.ResultFail {
			t.Errorf("token %q must be rejected, got %v", bad, c.Result())
		}
	}
}
