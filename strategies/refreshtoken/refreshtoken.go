// Package refreshtoken authenticates OAuth2-style refresh-token requests, the
// grant a client uses at a token endpoint to trade a long-lived refresh_token
// for a fresh access token. It mirrors the server side of the OAuth 2.0
// "refresh_token" grant (RFC 6749 section 6) rather than any single Passport.js
// module, and complements strategies/refreshjwt: use this one when refresh
// tokens are opaque strings tracked in your own store, and refreshjwt when they
// are self-contained signed JWTs.
//
// Use this strategy on the /oauth/token (or equivalent) endpoint of an
// authorization server or API. The client POSTs its refresh token there when its
// access token expires; the strategy extracts and validates the token, and on
// success the handler mints and returns a new access token (and optionally a
// rotated refresh token). Because validation goes through a user-supplied Verify
// function backed by your store, you can implement revocation, expiry, rotation
// and reuse detection there — capabilities a stateless JWT cannot offer.
//
// The refresh_token is read from the request body in either of the two encodings
// real OAuth clients use: an application/x-www-form-urlencoded form field named
// "refresh_token" (selected for any non-JSON content type), or a JSON object with
// a "refresh_token" property (selected when the Content-Type is
// application/json). The strategy reads the body fully and then restores it (via
// an io.NopCloser wrapper) so downstream handlers can read it again. A request
// with no extractable token is a 401 failure ("Missing refresh token").
//
// The Verify function receives the raw token and returns the authenticated user.
// Returning the sentinel ErrInvalidToken (which callers may use for an invalid,
// expired or revoked token) is treated as a 401 authentication failure ("Invalid
// refresh token"), as is returning a nil user with a nil error. Any other
// non-nil error is reported as an internal error rather than a failure, so
// transient store errors are not confused with bad credentials.
//
// Parity and security notes: this strategy only authenticates the presented
// refresh token; issuing the new access token, and any rotation or one-time-use
// enforcement, are the handler's responsibility. For rotation with reuse
// detection, invalidate the old token in your store when a new one is issued and
// treat a second presentation of a rotated token as a breach. Always serve the
// token endpoint over TLS and require client authentication where appropriate.
package refreshtoken

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/malcolmston/passport"
)

// ErrInvalidToken is a convenience sentinel a Verify func may return to signal
// an invalid or revoked refresh token (treated as an authentication failure).
var ErrInvalidToken = errors.New("invalid refresh token")

// VerifyFunc validates a refresh token, returning the authenticated user.
type VerifyFunc func(token string) (user any, err error)

// Strategy authenticates requests presenting a refresh token in their body.
type Strategy struct {
	verify VerifyFunc
}

// New creates a refreshtoken Strategy.
func New(verify VerifyFunc) *Strategy {
	return &Strategy{verify: verify}
}

// Name returns "refresh-token".
func (s *Strategy) Name() string { return "refresh-token" }

// Authenticate implements passport.Strategy.
func (s *Strategy) Authenticate(c *passport.Context, r *http.Request) {
	token := s.extract(c, r)
	if c.Result() == passport.ResultError {
		return
	}
	if token == "" {
		c.Fail("Missing refresh token", http.StatusUnauthorized)
		return
	}
	user, err := s.verify(token)
	if err != nil {
		if errors.Is(err, ErrInvalidToken) {
			c.Fail("Invalid refresh token", http.StatusUnauthorized)
			return
		}
		c.Error(err)
		return
	}
	if user == nil {
		c.Fail("Invalid refresh token", http.StatusUnauthorized)
		return
	}
	c.Success(user)
}

// extract reads the body once, restores it, and pulls out the refresh_token.
func (s *Strategy) extract(c *passport.Context, r *http.Request) string {
	if r.Body == nil {
		return ""
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		c.Error(err)
		return ""
	}
	r.Body = io.NopCloser(bytes.NewReader(body))

	ct := r.Header.Get("Content-Type")
	if strings.HasPrefix(ct, "application/json") {
		var payload struct {
			RefreshToken string `json:"refresh_token"`
		}
		if err := json.Unmarshal(body, &payload); err == nil {
			return payload.RefreshToken
		}
		return ""
	}
	if values, err := url.ParseQuery(string(body)); err == nil {
		return values.Get("refresh_token")
	}
	return ""
}
