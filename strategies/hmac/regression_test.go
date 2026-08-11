package hmac

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/malcolmston/passport"
)

var testSecret = []byte("shared-webhook-secret")

func signBody(body string) string {
	mac := hmac.New(sha256.New, testSecret)
	mac.Write([]byte(body))
	return hex.EncodeToString(mac.Sum(nil))
}

func post(t *testing.T, s *Strategy, body, sig string) *passport.Context {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, "/hook", strings.NewReader(body))
	r.Header.Set("X-Signature", sig)
	c := &passport.Context{}
	s.Authenticate(c, r)
	return c
}

func newTestStrategy(maxBody int64) *Strategy {
	return New(Options{
		Secret:       func(string) []byte { return testSecret },
		MaxBodyBytes: maxBody,
	})
}

// TestSignatureCaseInsensitive covers the switch from comparing hex strings to
// comparing decoded bytes. Senders differ on hex case, and rejecting a valid
// signature because it arrived upper-cased is a real interoperability bug.
func TestSignatureCaseInsensitive(t *testing.T) {
	const body = `{"event":"ping"}`
	s := newTestStrategy(0)

	for _, sig := range []string{signBody(body), strings.ToUpper(signBody(body))} {
		if c := post(t, s, body, sig); c.Result() != passport.ResultSuccess {
			t.Errorf("signature %q rejected: %v", sig, c.Result())
		}
	}
}

// TestNonHexSignatureRejected makes sure garbage in the signature header fails
// cleanly rather than being compared as raw bytes.
func TestNonHexSignatureRejected(t *testing.T) {
	const body = `{"event":"ping"}`
	s := newTestStrategy(0)
	for _, sig := range []string{"zzzz", "not a signature", signBody(body) + "x", signBody(body)[:63]} {
		if c := post(t, s, body, sig); c.Result() != passport.ResultFail {
			t.Errorf("signature %q must be rejected, got %v", sig, c.Result())
		}
	}
}

// TestWrongSignatureRejected is the base case: the digest must actually be
// checked against the body.
func TestWrongSignatureRejected(t *testing.T) {
	s := newTestStrategy(0)
	if c := post(t, s, `{"event":"ping"}`, signBody(`{"event":"pong"}`)); c.Result() != passport.ResultFail {
		t.Error("a signature over different bytes was accepted")
	}
}

// TestBodyLimit pins the cap on how much an unauthenticated caller can make the
// process buffer. Verification needs the whole body in memory before the caller
// is known, so without a limit a single request can allocate without bound.
func TestBodyLimit(t *testing.T) {
	s := newTestStrategy(64)

	small := strings.Repeat("a", 64)
	if c := post(t, s, small, signBody(small)); c.Result() != passport.ResultSuccess {
		t.Fatalf("a body exactly at the limit must be accepted, got %v", c.Result())
	}

	big := strings.Repeat("a", 65)
	c := post(t, s, big, signBody(big))
	if c.Result() != passport.ResultFail {
		t.Errorf("a body over the limit must be rejected, got %v", c.Result())
	}
	if c.Challenge() != "Request body too large" {
		t.Errorf("challenge = %q, want the size-specific message", c.Challenge())
	}
}

// TestBodyLimitDisabled confirms a negative cap opts out entirely.
func TestBodyLimitDisabled(t *testing.T) {
	s := newTestStrategy(-1)
	body := strings.Repeat("x", 1<<20)
	if c := post(t, s, body, signBody(body)); c.Result() != passport.ResultSuccess {
		t.Errorf("with the limit disabled a large signed body must pass, got %v", c.Result())
	}
}

// TestBodyRestoredForHandler checks that consuming the body to verify it does
// not deprive the downstream handler of the payload.
func TestBodyRestoredForHandler(t *testing.T) {
	const body = `{"event":"ping"}`
	s := newTestStrategy(0)

	r := httptest.NewRequest(http.MethodPost, "/hook", strings.NewReader(body))
	r.Header.Set("X-Signature", signBody(body))
	c := &passport.Context{}
	s.Authenticate(c, r)
	if c.Result() != passport.ResultSuccess {
		t.Fatalf("Result() = %v", c.Result())
	}

	got, err := io.ReadAll(r.Body)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, []byte(body)) {
		t.Errorf("downstream body = %q, want %q", got, body)
	}
}

// TestUnknownKeyID checks the key-rotation path: an unrecognized key id must be
// rejected before any digest is computed.
func TestUnknownKeyID(t *testing.T) {
	s := New(Options{
		KeyIDHeader: "X-Key-Id",
		Secret: func(keyID string) []byte {
			if keyID == "live" {
				return testSecret
			}
			return nil
		},
	})

	const body = "{}"
	for _, tt := range []struct {
		keyID string
		want  passport.Result
	}{
		{"live", passport.ResultSuccess},
		{"revoked", passport.ResultFail},
		{"", passport.ResultFail},
	} {
		r := httptest.NewRequest(http.MethodPost, "/hook", strings.NewReader(body))
		r.Header.Set("X-Signature", signBody(body))
		r.Header.Set("X-Key-Id", tt.keyID)
		c := &passport.Context{}
		s.Authenticate(c, r)
		if c.Result() != tt.want {
			t.Errorf("key id %q: Result() = %v, want %v", tt.keyID, c.Result(), tt.want)
		}
	}
}
