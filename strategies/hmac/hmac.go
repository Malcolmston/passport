// Package hmac authenticates requests by verifying an HMAC-SHA256 signature of
// the raw request body. The signature is read from a configurable header
// (default "X-Signature") as lowercase hex and compared in constant time
// against a signature computed with a per-key secret. On a match the key id is
// used as the authenticated user.
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
