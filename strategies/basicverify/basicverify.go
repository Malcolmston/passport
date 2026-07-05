// Package basicverify implements HTTP Basic authentication (RFC 7617) with a
// user-supplied verify function and a configurable realm. It is a self-contained
// sibling of strategies/basic and the same conceptual port of the BasicStrategy
// from Passport.js's passport-http, packaged with an Options struct so the realm
// can be set explicitly.
//
// Use it where you want Basic auth but need control over the realm reported to
// clients — for example to present a specific application name in the browser's
// credential prompt, or to distinguish protected areas. Like Basic auth
// generally it should run over HTTPS and is usually mounted statelessly with
// passport.Options{Session: false}.
//
// On each request the strategy decodes the "Basic base64(user:pass)"
// Authorization header and passes the username and password to Options.Verify.
// When the header is missing or invalid, or verification fails, it records a
// Basic realm="<Realm>" challenge (Realm defaults to "Users") and, when a
// response writer is available on the context, also sets the WWW-Authenticate
// response header so browsers re-prompt.
//
// The verify contract mirrors the other credential strategies: a non-nil user
// authenticates; (nil, nil) or (nil, ErrInvalidCredentials) is an authentication
// failure that re-issues the challenge; and (nil, err) is an internal error.
// Verify should compare against a stored password hash rather than a plaintext
// value.
//
// Parity: functionally identical to passport-http's BasicStrategy for the verify
// form, differing from the bundled strategies/basic only in exposing the realm
// through Options and in proactively writing the WWW-Authenticate header. It
// registers under the name "basic-verify" so it can coexist with the "basic"
// strategy in the same passport.Passport.
package basicverify

import (
	"encoding/base64"
	"errors"
	"net/http"
	"strings"

	"github.com/malcolmston/passport"
)

// ErrInvalidCredentials is a convenience sentinel a Verify func may return to
// signal bad credentials (treated as an authentication failure).
var ErrInvalidCredentials = errors.New("invalid credentials")

// VerifyFunc validates a username/password pair, returning the authenticated
// user on success.
type VerifyFunc func(username, password string) (user any, err error)

// Options configures the basicverify Strategy.
type Options struct {
	// Realm is reported in the WWW-Authenticate challenge. Defaults to "Users".
	Realm string
	// Verify validates the decoded credentials.
	Verify VerifyFunc
}

// Strategy authenticates requests using HTTP Basic credentials.
type Strategy struct {
	realm  string
	verify VerifyFunc
}

// New creates a basicverify Strategy. opts.Realm defaults to "Users".
func New(opts Options) *Strategy {
	realm := opts.Realm
	if realm == "" {
		realm = "Users"
	}
	return &Strategy{realm: realm, verify: opts.Verify}
}

// Name returns "basic-verify".
func (s *Strategy) Name() string { return "basic-verify" }

// Authenticate implements passport.Strategy.
func (s *Strategy) Authenticate(c *passport.Context, r *http.Request) {
	username, password, ok := parseBasicAuth(r.Header.Get("Authorization"))
	if !ok {
		s.challenge(c)
		return
	}
	user, err := s.verify(username, password)
	if err != nil {
		if errors.Is(err, ErrInvalidCredentials) {
			s.challenge(c)
			return
		}
		c.Error(err)
		return
	}
	if user == nil {
		s.challenge(c)
		return
	}
	c.Success(user)
}

// challenge records a Basic WWW-Authenticate challenge and also sets the header
// when a response writer is available on the context.
func (s *Strategy) challenge(c *passport.Context) {
	value := "Basic realm=\"" + s.realm + "\""
	if c.Writer != nil {
		c.Writer.Header().Set("WWW-Authenticate", value)
	}
	c.Fail(value, http.StatusUnauthorized)
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
