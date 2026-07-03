// Package digest implements a SIMPLIFIED form of HTTP Digest access
// authentication (RFC 7616) using MD5 and qop="auth".
//
// When a request carries no Digest Authorization header, the strategy fails
// with a "Digest realm=..., nonce=..., qop=auth" challenge suitable for a
// WWW-Authenticate response header. When a Digest header is present, the
// response digest is recomputed from the supplied parameters and the user's
// secret and compared in constant time.
//
// SIMPLIFICATION: this implementation does NOT track issued nonces, nonce
// counts (nc), or opaque values, so it does not defend against replay attacks
// and it accepts any well-formed nonce echoed by the client. Do not use it as
// the sole protection for sensitive resources; layer it over TLS and, for real
// replay protection, add server-side nonce/nc bookkeeping.
package digest

import (
	"crypto/md5"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"net/http"
	"strings"

	"github.com/malcolmston/passport"
)

// Options configures the digest Strategy.
type Options struct {
	// Realm is the protection space presented in the challenge.
	Realm string
	// Secret returns the password (or precomputed HA1) for the given username.
	// The returned value is treated as the cleartext password from which HA1 =
	// MD5(username:realm:password) is derived. An empty return rejects the user.
	Secret func(user string) (ha1OrPassword string)
	// Nonce, when set, returns the challenge nonce; defaults to a random value.
	// Injected for deterministic tests.
	Nonce func() string
}

// Strategy authenticates requests using simplified HTTP Digest.
type Strategy struct {
	realm  string
	secret func(user string) string
	nonce  func() string
}

// New creates a digest Strategy. opts.Realm defaults to "Users".
func New(opts Options) *Strategy {
	realm := opts.Realm
	if realm == "" {
		realm = "Users"
	}
	nonce := opts.Nonce
	if nonce == nil {
		nonce = randomNonce
	}
	return &Strategy{realm: realm, secret: opts.Secret, nonce: nonce}
}

// Name returns "digest".
func (s *Strategy) Name() string { return "digest" }

// Authenticate implements passport.Strategy.
func (s *Strategy) Authenticate(c *passport.Context, r *http.Request) {
	h := r.Header.Get("Authorization")
	if len(h) < 7 || !strings.EqualFold(h[:7], "digest ") {
		s.challenge(c)
		return
	}
	params := parseParams(h[7:])
	username := params["username"]
	if username == "" || params["response"] == "" {
		s.challenge(c)
		return
	}
	password := s.secret(username)
	if password == "" {
		s.challenge(c)
		return
	}

	ha1 := md5hex(username + ":" + s.realm + ":" + password)
	ha2 := md5hex(r.Method + ":" + params["uri"])

	var response string
	if params["qop"] != "" {
		response = md5hex(strings.Join([]string{
			ha1, params["nonce"], params["nc"], params["cnonce"], params["qop"], ha2,
		}, ":"))
	} else {
		response = md5hex(ha1 + ":" + params["nonce"] + ":" + ha2)
	}

	if subtle.ConstantTimeCompare([]byte(response), []byte(params["response"])) != 1 {
		s.challenge(c)
		return
	}
	c.Success(username)
}

// challenge records a Digest WWW-Authenticate challenge with a fresh nonce.
func (s *Strategy) challenge(c *passport.Context) {
	value := "Digest realm=\"" + s.realm + "\", nonce=\"" + s.nonce() + "\", qop=\"auth\""
	if c.Writer != nil {
		c.Writer.Header().Set("WWW-Authenticate", value)
	}
	c.Fail(value, http.StatusUnauthorized)
}

func md5hex(s string) string {
	sum := md5.Sum([]byte(s))
	return hex.EncodeToString(sum[:])
}

func randomNonce() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// parseParams parses a comma-separated list of key=value digest parameters,
// stripping optional surrounding double quotes from values.
func parseParams(s string) map[string]string {
	out := make(map[string]string)
	for _, part := range splitParams(s) {
		eq := strings.IndexByte(part, '=')
		if eq < 0 {
			continue
		}
		key := strings.TrimSpace(part[:eq])
		val := strings.TrimSpace(part[eq+1:])
		val = strings.Trim(val, "\"")
		out[key] = val
	}
	return out
}

// splitParams splits on commas that are not inside double quotes.
func splitParams(s string) []string {
	var parts []string
	var b strings.Builder
	inQuote := false
	for _, r := range s {
		switch {
		case r == '"':
			inQuote = !inQuote
			b.WriteRune(r)
		case r == ',' && !inQuote:
			parts = append(parts, b.String())
			b.Reset()
		default:
			b.WriteRune(r)
		}
	}
	if b.Len() > 0 {
		parts = append(parts, b.String())
	}
	return parts
}
