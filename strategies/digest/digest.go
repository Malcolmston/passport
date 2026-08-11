// Package digest implements a SIMPLIFIED form of HTTP Digest access
// authentication (RFC 7616) using MD5 and qop="auth". It is the Go port of the
// Passport.js passport-http Digest strategy: rather than transmitting a password,
// the client proves knowledge of it by sending a hash computed over a
// server-issued nonce, so the cleartext secret never travels on the wire.
//
// Use it when you want browser-native credential prompts without building a login
// form or when interoperating with clients (tools, devices, curl --digest) that
// speak Digest. Because the browser itself renders the username/password dialog
// in response to the challenge, there is no HTML frontend to write; the "frontend"
// is simply any request to a protected URL. Digest is stateless per request, so
// pair the strategy with passport.Options{Session: passport.NoSession()}.
//
// The exchange works in two steps. When a request carries no Digest Authorization
// header, the strategy fails with a "Digest realm=..., nonce=..., qop=auth"
// challenge, which it also sets as a WWW-Authenticate response header so the
// client knows how to respond. When a Digest header is present, the strategy looks
// up the user's secret via Options.Secret, recomputes the expected response digest
// from the request method, URI, realm, nonce, and (for qop) the client nonce and
// nonce count, and compares it against the client's value in constant time.
//
// Semantics and the verify contract: Options.Secret returns the cleartext
// password (or a precomputed HA1) for a username, and returning an empty string
// rejects that user by re-issuing the challenge. A malformed header, a missing
// username or response, or a digest mismatch all result in a fresh challenge
// rather than a hard error, which is how browsers are prompted to retry. On a
// successful match the username becomes the authenticated user (passport.User).
// Options.Realm defaults to "Users", and Options.Nonce may be injected to make the
// challenge deterministic in tests.
//
// SIMPLIFICATION and security caveats: by default this implementation does NOT
// track issued nonces, nonce counts (nc), or opaque values, so out of the box it
// does not defend against replay attacks and it accepts any well-formed nonce
// echoed by the client — a captured Authorization header stays valid
// indefinitely. Options.ValidateNonce is the hook for closing that gap: supply
// it with a store of the nonces this server issued and reject any it did not
// mint, has already seen at that nonce-count, or has expired. The scheme also
// uses MD5, which is weak. Do not use it as the sole protection for sensitive
// resources; layer it over TLS. The strategy registers under the name "digest".
package digest

import (
	"crypto/md5"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"net/http"
	"strings"

	"github.com/malcolmston/passport"
	"github.com/malcolmston/passport/httpauth"
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
	// ValidateNonce, when set, is consulted with the nonce and nonce-count the
	// client echoed back before the response digest is checked; returning
	// false re-issues the challenge.
	//
	// This is the hook that turns Digest from a "proves knowledge of the
	// password" check into one that also resists replay. Without it the
	// strategy computes the expected digest over whatever nonce the client
	// chose to send, so a captured Authorization header stays valid forever
	// and can be replayed by anyone who observed it. A production
	// implementation should record the nonces it issued, reject any it did not,
	// expire them, and refuse an (nonce, nc) pair it has already seen.
	//
	// It is left opt-in because the bookkeeping needs storage this
	// dependency-free strategy has no way to provide.
	ValidateNonce func(nonce, nc string) bool
}

// Strategy authenticates requests using simplified HTTP Digest.
type Strategy struct {
	realm         string
	secret        func(user string) string
	nonce         func() string
	validateNonce func(nonce, nc string) bool
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
	return &Strategy{
		realm:         realm,
		secret:        opts.Secret,
		nonce:         nonce,
		validateNonce: opts.ValidateNonce,
	}
}

// Name returns "digest".
func (s *Strategy) Name() string { return "digest" }

// Authenticate implements passport.Strategy. Its control flow mirrors
// passport-http's DigestStrategy, including its two rejection modes: a
// *malformed* request (a header with no space-separated credentials, no
// credentials at all, or one whose "uri" directive does not match the request
// target) is a client error and fails with HTTP 400 and NO challenge, whereas a
// missing header, a non-Digest scheme, a missing username, an unknown user, a
// spent nonce, or a digest mismatch re-issues the 401 Digest challenge.
func (s *Strategy) Authenticate(c *passport.Context, r *http.Request) {
	h := r.Header.Get("Authorization")
	if h == "" {
		s.challenge(c)
		return
	}
	// Upstream: `parts = authorization.split(' '); if (parts.length < 2) fail(400)`.
	sp := strings.IndexByte(h, ' ')
	if sp < 0 {
		c.Fail("", http.StatusBadRequest)
		return
	}
	scheme, rest := h[:sp], h[sp+1:]
	if !strings.EqualFold(scheme, "Digest") {
		s.challenge(c)
		return
	}
	// httpauth.ParseParams handles quoted-strings properly (backslash escapes,
	// commas inside quotes) and lower-cases the keys, so a client that quotes
	// a field this strategy reads is not silently misparsed.
	params := httpauth.ParseParams(rest)
	// Upstream: `if (Object.keys(creds).length === 0) fail(400)`.
	if len(params) == 0 {
		c.Fail("", http.StatusBadRequest)
		return
	}
	username := params["username"]
	if username == "" || params["response"] == "" {
		s.challenge(c)
		return
	}
	// URI binding (RFC 7616): the response is bound to the request-target the
	// client hashed into HA2. Upstream rejects `req.url !== creds.uri` with 400,
	// so one captured Authorization header cannot authenticate a different path.
	// Compare against the request-target as the client sent it (path plus raw
	// query), which is exactly what a conforming client puts in the "uri" field.
	if params["uri"] != r.URL.RequestURI() {
		c.Fail("", http.StatusBadRequest)
		return
	}
	if s.validateNonce != nil && !s.validateNonce(params["nonce"], params["nc"]) {
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
// The realm and nonce are emitted as quoted-strings so neither can terminate
// the header value or inject a second one.
func (s *Strategy) challenge(c *passport.Context) {
	value := httpauth.DigestChallenge(httpauth.DigestChallengeParams{
		Realm: s.realm,
		Nonce: s.nonce(),
		QOP:   "auth",
	})
	if c.Writer != nil {
		c.Writer.Header().Set("WWW-Authenticate", value)
	}
	c.Fail(value, http.StatusUnauthorized)
}

func md5hex(s string) string {
	sum := md5.Sum([]byte(s))
	return hex.EncodeToString(sum[:])
}

// randomNonce returns 128 bits of hex-encoded entropy for the challenge.
//
// A nonce that an attacker can predict undermines the whole exchange, so a
// failure of the system random source must not be papered over: rather than
// return an all-zero nonce, panic. On any platform this runs on, crypto/rand
// failing means the process has no usable entropy source and cannot
// meaningfully authenticate anyone.
func randomNonce() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic("digest: crypto/rand unavailable, cannot issue a nonce: " + err.Error())
	}
	return hex.EncodeToString(b)
}
