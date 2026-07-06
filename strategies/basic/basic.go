// Package basic implements HTTP Basic authentication (RFC 7617) for the passport
// port. It is a Go port of the BasicStrategy from Passport.js's passport-http:
// credentials arrive base64-encoded in the Authorization header, and a
// user-supplied VerifyFunc maps the decoded username and password to an
// application user.
//
// Basic authentication is a good fit for simple, internal, or machine-to-machine
// endpoints, admin tools, and health/metrics routes where a browser's built-in
// credential prompt or a scripted client (curl -u, an SDK) is acceptable.
// Because the credentials are sent on every request it should only be used over
// HTTPS, and it is typically mounted statelessly with
// passport.Options{Session: false}.
//
// On each request the strategy parses the "Basic base64(user:pass)"
// Authorization header. If the header is missing or malformed it fails with a
// 401 and a WWW-Authenticate challenge of the form Basic realm="<Realm>" (the
// Realm field, defaulting to "Users", is what browsers show in their prompt).
// When the header parses, the decoded username and password are handed to
// VerifyFunc.
//
// The VerifyFunc contract has three outcomes: a non-nil user authenticates the
// request; (nil, nil) or (nil, ErrInvalidCredentials) is an authentication
// failure that re-issues the Basic challenge; and (nil, err) for any other error
// is treated as an internal error. Implementations should compare the password
// against a stored hash (bcrypt, scrypt, argon2) rather than a plaintext value
// and avoid leaking through timing.
//
// Parity: this matches passport-http's BasicStrategy for the single
// username/password verify form and its realm-based challenge, while leaving
// credential storage and hashing to VerifyFunc. The password-only signature and
// HTTP Digest support from passport-http are not included; for a
// realm-configurable variant with the same behavior see strategies/basicverify.
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
