// Package refreshtoken authenticates OAuth2-style refresh-token requests. The
// refresh_token is read from the request body — either an
// application/x-www-form-urlencoded form field or a JSON object — and validated
// by a user-supplied Verify function. The request body is fully read and then
// restored so downstream handlers can read it again.
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
