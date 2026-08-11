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
// passport.Options{Session: passport.NoSession()}.
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
	"github.com/malcolmston/passport/httpauth"
)

// ErrInvalidCredentials is a convenience sentinel a VerifyFunc may return to
// signal bad credentials (treated as an authentication failure).
var ErrInvalidCredentials = errors.New("invalid credentials")

// VerifyFunc validates a username/password pair, returning the authenticated
// user on success.
type VerifyFunc func(username, password string) (user any, err error)

// Strategy authenticates requests using HTTP Basic credentials.
type Strategy struct {
	// Realm is reported in the WWW-Authenticate challenge on failure. It is
	// rendered as a quoted-string by httpauth.BasicChallenge, so embedded
	// quotes, backslashes and control characters cannot break out of the
	// header value.
	Realm string

	verify VerifyFunc
}

// New creates a basic Strategy.
func New(verify VerifyFunc) *Strategy {
	return &Strategy{Realm: "Users", verify: verify}
}

// Name returns "basic".
func (s *Strategy) Name() string { return "basic" }

// Authenticate implements passport.Strategy. Its control flow mirrors
// passport-http's BasicStrategy exactly, including its two distinct rejection
// modes: a *syntactically malformed* header (no space-separated credentials, or
// a payload that decodes without a "user:pass" colon) is a client error and
// fails with HTTP 400 and NO challenge, whereas a missing header, a non-Basic
// scheme, empty credentials, or a verify rejection re-issues the 401 Basic
// challenge.
func (s *Strategy) Authenticate(c *passport.Context, r *http.Request) {
	authorization := r.Header.Get("Authorization")
	if authorization == "" {
		c.FailWithChallenge(httpauth.BasicChallenge(s.Realm), http.StatusUnauthorized)
		return
	}
	// Upstream: `parts = authorization.split(' '); if (parts.length < 2) fail(400)`.
	parts := strings.Split(authorization, " ")
	if len(parts) < 2 {
		c.Fail("", http.StatusBadRequest)
		return
	}
	scheme := parts[0]
	// Upstream decodes with Node's Buffer(x,'base64'), which is lenient: it
	// ignores characters outside the base64 alphabet and tolerates missing
	// padding. Mirror that so the same inputs decode to the same bytes.
	decoded := lenientBase64(parts[1])
	if !strings.EqualFold(scheme, httpauth.SchemeBasic) {
		c.FailWithChallenge(httpauth.BasicChallenge(s.Realm), http.StatusUnauthorized)
		return
	}
	// Upstream: `credentials = decoded.split(':'); if (credentials.length < 2) fail(400)`.
	idx := strings.IndexByte(decoded, ':')
	if idx < 0 {
		c.Fail("", http.StatusBadRequest)
		return
	}
	username, password := decoded[:idx], decoded[idx+1:]
	// Parity with passport-http: credentials lacking a username or a password
	// fail with the challenge without invoking the verify callback
	// (upstream: `if (!userid || !password) return this.fail(this._challenge())`).
	if username == "" || password == "" {
		c.FailWithChallenge(httpauth.BasicChallenge(s.Realm), http.StatusUnauthorized)
		return
	}
	user, err := s.verify(username, password)
	if err != nil {
		if errors.Is(err, ErrInvalidCredentials) {
			c.FailWithChallenge(httpauth.BasicChallenge(s.Realm), http.StatusUnauthorized)
			return
		}
		c.Error(err)
		return
	}
	if user == nil {
		c.FailWithChallenge(httpauth.BasicChallenge(s.Realm), http.StatusUnauthorized)
		return
	}
	c.Success(user)
}

// lenientBase64 decodes s the way Node's Buffer.from(s, "base64") does: it
// discards any byte outside the standard base64 alphabet and tolerates absent
// padding, decoding the largest valid prefix rather than failing outright. The
// standard library's decoders are strict, so an attacker-supplied payload that
// upstream would decode (to bytes that then lack a ":" separator, yielding a
// 400) must decode here too, to the same bytes.
func lenientBase64(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
			(c >= '0' && c <= '9') || c == '+' || c == '/' {
			b.WriteByte(c)
		}
	}
	clean := b.String()
	// A base64 group is 4 chars; a trailing length of 1 encodes no whole byte,
	// so drop it (Node does the same rather than erroring).
	if len(clean)%4 == 1 {
		clean = clean[:len(clean)-1]
	}
	dec, err := base64.RawStdEncoding.DecodeString(clean)
	if err != nil {
		return ""
	}
	return string(dec)
}
