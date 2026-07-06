// Package hmac authenticates requests by verifying an HMAC-SHA256 signature of
// the raw request body. It ports the HMAC request-signing pattern seen in the
// Passport.js ecosystem (passport-hmac) and in widely used webhook signature
// schemes such as Stripe's and GitHub's, using only the Go standard library.
//
// Use this strategy to authenticate webhook deliveries and other machine-to-
// machine POST requests where the sender and receiver share a secret and the
// sender signs each payload. Because the signature covers the exact bytes of
// the body, it authenticates the caller and guarantees the payload was not
// altered in transit, without any interactive handshake or session. This makes
// it well suited to receiving events from third-party providers that sign their
// callbacks, or to securing internal service-to-service notifications.
//
// The flow reads the hex-encoded signature from the header named by
// Options.Header (defaulting to "X-Signature") and an optional key id from
// Options.KeyIDHeader. The key id is passed to Options.Secret to look up the
// shared secret; when KeyIDHeader is empty the strategy verifies against
// Secret(""). The strategy recomputes HMAC-SHA256 over the raw request body
// with that secret, hex-encodes it, and compares it against the presented
// signature using a constant-time comparison (hmac.Equal). A missing signature,
// an unknown key id (Secret returns nil), or a mismatch fails the request with
// 401; on a match the key id becomes the authenticated user available through
// passport.User(r).
//
// Two details are important for correctness. First, verification is over the
// raw, unparsed request body, so the signed bytes must be exactly what the
// sender signed; the strategy buffers the body while reading it and restores it
// via an io.NopCloser so downstream handlers can still read the payload.
// Second, the secret is resolved per request through the Secret(keyID)
// callback, which supports multiple clients and key rotation: returning nil for
// an unrecognized key id cleanly rejects the request, and the signature
// comparison is constant-time to avoid leaking validity through timing.
//
// Parity with Passport.js: like the Node HMAC strategies and provider webhook
// verifiers, this recomputes a keyed digest of the request body and compares it
// against a client-supplied signature, then reports the verified identity (the
// key id) to the framework. The header names and per-key secret lookup are
// configurable to match a given provider's signing scheme. The Strategy's
// registered name is "hmac".
package hmac

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"

	"github.com/malcolmston/passport"
)

// Options configures the hmac Strategy.
type Options struct {
	// Secret returns the shared secret for the given key id, or nil if the key
	// id is unknown.
	Secret func(keyID string) []byte
	// Header carries the hex-encoded signature. Defaults to "X-Signature".
	Header string
	// KeyIDHeader carries the key id used to look up the secret. When empty the
	// signature is verified against Secret("").
	KeyIDHeader string
}

// Strategy authenticates requests bearing an HMAC-SHA256 body signature.
type Strategy struct {
	secret      func(keyID string) []byte
	header      string
	keyIDHeader string
}

// New creates an hmac Strategy. opts.Header defaults to "X-Signature".
func New(opts Options) *Strategy {
	header := opts.Header
	if header == "" {
		header = "X-Signature"
	}
	return &Strategy{secret: opts.Secret, header: header, keyIDHeader: opts.KeyIDHeader}
}

// Name returns "hmac".
func (s *Strategy) Name() string { return "hmac" }

// Authenticate implements passport.Strategy.
func (s *Strategy) Authenticate(c *passport.Context, r *http.Request) {
	sig := r.Header.Get(s.header)
	if sig == "" {
		c.Fail("Missing signature", http.StatusUnauthorized)
		return
	}
	keyID := ""
	if s.keyIDHeader != "" {
		keyID = r.Header.Get(s.keyIDHeader)
	}
	secret := s.secret(keyID)
	if secret == nil {
		c.Fail("Unknown key", http.StatusUnauthorized)
		return
	}

	var body []byte
	if r.Body != nil {
		b, err := io.ReadAll(r.Body)
		if err != nil {
			c.Error(err)
			return
		}
		body = b
		r.Body = io.NopCloser(bytes.NewReader(body))
	}

	mac := hmac.New(sha256.New, secret)
	mac.Write(body)
	expected := hex.EncodeToString(mac.Sum(nil))

	if !hmac.Equal([]byte(sig), []byte(expected)) {
		c.Fail("Invalid signature", http.StatusUnauthorized)
		return
	}
	c.Success(keyID)
}
