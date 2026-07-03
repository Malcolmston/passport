// Package clientcredentials implements OAuth2 client-credentials style
// authentication. The client_id and client_secret are read either from the HTTP
// Basic Authorization header (RFC 6749 §2.3.1) or from the request form body,
// and validated by a user-supplied Verify function.
package clientcredentials

import (
	"encoding/base64"
	"errors"
	"net/http"
	"strings"

	"github.com/malcolmston/passport"
)

// ErrInvalidClient is a convenience sentinel a Verify func may return to signal
// invalid client credentials (treated as an authentication failure).
var ErrInvalidClient = errors.New("invalid client")

// VerifyFunc validates a client id/secret pair, returning the authenticated
// client (user) on success.
type VerifyFunc func(id, secret string) (user any, err error)

// Strategy authenticates OAuth2 clients using the client-credentials grant.
type Strategy struct {
	verify VerifyFunc
}

// New creates a clientcredentials Strategy.
func New(verify VerifyFunc) *Strategy {
	return &Strategy{verify: verify}
}

// Name returns "client-credentials".
func (s *Strategy) Name() string { return "client-credentials" }

// Authenticate implements passport.Strategy.
func (s *Strategy) Authenticate(c *passport.Context, r *http.Request) {
	id, secret, ok := credentials(r)
	if !ok {
		c.Fail("Basic", http.StatusUnauthorized)
		return
	}
	user, err := s.verify(id, secret)
	if err != nil {
		if errors.Is(err, ErrInvalidClient) {
			c.Fail("invalid_client", http.StatusUnauthorized)
			return
		}
		c.Error(err)
		return
	}
	if user == nil {
		c.Fail("invalid_client", http.StatusUnauthorized)
		return
	}
	c.Success(user)
}

// credentials extracts the client id/secret from the Basic header first, then
// falls back to the form body.
func credentials(r *http.Request) (id, secret string, ok bool) {
	if h := r.Header.Get("Authorization"); len(h) >= 6 && strings.EqualFold(h[:6], "basic ") {
		if decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(h[6:])); err == nil {
			creds := string(decoded)
			if i := strings.IndexByte(creds, ':'); i >= 0 {
				return creds[:i], creds[i+1:], true
			}
		}
	}
	if err := r.ParseForm(); err == nil {
		id = r.PostFormValue("client_id")
		secret = r.PostFormValue("client_secret")
		if id != "" {
			return id, secret, true
		}
	}
	return "", "", false
}
