// Package basic implements HTTP Basic authentication (RFC 7617), a Go port of
// passport-http's BasicStrategy. Credentials are read from the Authorization
// header and validated by a user-supplied VerifyFunc.
package basic

import (
	"encoding/base64"
	"errors"
	"net/http"
	"strings"

	"github.com/malcolmston/passport"
)

// ErrInvalidCredentials is a convenience sentinel a VerifyFunc may return to
// signal bad credentials (treated as an authentication failure).
var ErrInvalidCredentials = errors.New("invalid credentials")

// VerifyFunc validates a username/password pair, returning the authenticated
// user on success.
type VerifyFunc func(username, password string) (user any, err error)

// Strategy authenticates requests using HTTP Basic credentials.
type Strategy struct {
	// Realm is reported in the WWW-Authenticate challenge on failure.
	Realm string

	verify VerifyFunc
}

// New creates a basic Strategy.
func New(verify VerifyFunc) *Strategy {
	return &Strategy{Realm: "Users", verify: verify}
}

// Name returns "basic".
func (s *Strategy) Name() string { return "basic" }

// Authenticate implements passport.Strategy.
func (s *Strategy) Authenticate(c *passport.Context, r *http.Request) {
	username, password, ok := parseBasicAuth(r.Header.Get("Authorization"))
	if !ok {
		c.Fail("Basic realm=\""+s.Realm+"\"", http.StatusUnauthorized)
		return
	}
	user, err := s.verify(username, password)
	if err != nil {
		if errors.Is(err, ErrInvalidCredentials) {
			c.Fail("Basic realm=\""+s.Realm+"\"", http.StatusUnauthorized)
			return
		}
		c.Error(err)
		return
	}
	if user == nil {
		c.Fail("Basic realm=\""+s.Realm+"\"", http.StatusUnauthorized)
		return
	}
	c.Success(user)
}

// parseBasicAuth decodes a "Basic base64(user:pass)" Authorization header.
func parseBasicAuth(header string) (username, password string, ok bool) {
	if len(header) < 6 || !strings.EqualFold(header[:6], "basic ") {
		return "", "", false
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(header[6:]))
	if err != nil {
		return "", "", false
	}
	creds := string(decoded)
	i := strings.IndexByte(creds, ':')
	if i < 0 {
		return "", "", false
	}
	return creds[:i], creds[i+1:], true
}
