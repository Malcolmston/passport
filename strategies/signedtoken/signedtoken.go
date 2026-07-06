// Package signedtoken implements self-contained, stateless bearer-token
// authentication using HMAC-SHA256-signed JSON claims. A token carries its own
// claims object signed with a shared secret, so any process holding that secret
// can verify it without a database lookup or session store. It fills the same
// niche as the token strategies in the Passport.js ecosystem (passport-http-bearer
// and JWT-style strategies), but with a deliberately minimal, dependency-free
// token format rather than full JWT/JOSE.
//
// Reach for this package for machine-to-machine and API authentication, where a
// caller presents a token on every request instead of maintaining a cookie
// session. It is a natural fit for single-page-app and mobile back ends, internal
// service-to-service calls, and short-lived signed links. Because verification is
// stateless it scales horizontally with no shared session store; the only shared
// state required is the HMAC secret. Pair it with passport.Options{Session: false}
// when you want purely stateless request authentication with no cookie.
//
// The token is a compact two-part string:
//
//	base64url(JSON claims) + "." + hex(HMAC-SHA256(base64url(JSON claims)))
//
// Mint a token with Sign and hand it to the client (typically at login or during
// provisioning); the client then sends it back on each request in the
// "Authorization: Bearer <token>" header. On each request the Strategy re-computes
// the HMAC over the payload and compares it in constant time (crypto/hmac.Equal)
// before decoding the claims. On success the decoded claims map becomes the
// authenticated user, readable via passport.User.
//
// Important semantics: the signature covers the payload, so any tampering with the
// claims invalidates the token. If the claims include a numeric "exp" field (Unix
// seconds) it is enforced against the injected clock (Now, defaulting to time.Now),
// and an expired token fails. The token is not encrypted — the claims are only
// base64url-encoded and are readable by anyone holding the token — so never place
// secrets in the claims. Because tokens are self-contained they cannot be revoked
// before expiry without an external denylist; keep lifetimes short and rotate the
// secret to invalidate outstanding tokens.
//
// Parity note: this is not a general-purpose JWT library. It intentionally fixes
// the algorithm to HMAC-SHA256, avoids the JOSE header and the algorithm-confusion
// pitfalls that come with it, and only understands the "exp" claim. If you need
// RS256/ES256, standard JWT claims, or interoperability with third-party JWT
// consumers, use a dedicated JWT strategy instead.
package signedtoken

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/malcolmston/passport"
)

// Sign encodes claims into a signed token using secret.
func Sign(secret []byte, claims map[string]any) (string, error) {
	raw, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	payload := base64.RawURLEncoding.EncodeToString(raw)
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(payload))
	sig := hex.EncodeToString(mac.Sum(nil))
	return payload + "." + sig, nil
}

// Options configures the signedtoken Strategy.
type Options struct {
	// Secret is the HMAC key used to verify tokens.
	Secret []byte
	// Now returns the current time; defaults to time.Now. Injected for tests.
	Now func() time.Time
}

// Strategy authenticates requests bearing a self-contained signed token.
type Strategy struct {
	secret []byte
	now    func() time.Time
}

// New creates a signedtoken Strategy.
func New(opts Options) *Strategy {
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	return &Strategy{secret: opts.Secret, now: now}
}

// Name returns "signed-token".
func (s *Strategy) Name() string { return "signed-token" }

// Authenticate implements passport.Strategy.
func (s *Strategy) Authenticate(c *passport.Context, r *http.Request) {
	h := r.Header.Get("Authorization")
	if len(h) < 7 || !strings.EqualFold(h[:7], "bearer ") {
		c.Fail("Missing token", http.StatusUnauthorized)
		return
	}
	token := strings.TrimSpace(h[7:])
	dot := strings.LastIndexByte(token, '.')
	if dot < 0 {
		c.Fail("Malformed token", http.StatusUnauthorized)
		return
	}
	payload, sig := token[:dot], token[dot+1:]

	mac := hmac.New(sha256.New, s.secret)
	mac.Write([]byte(payload))
	expected := hex.EncodeToString(mac.Sum(nil))
	if !hmac.Equal([]byte(sig), []byte(expected)) {
		c.Fail("Invalid signature", http.StatusUnauthorized)
		return
	}

	raw, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil {
		c.Fail("Malformed token", http.StatusUnauthorized)
		return
	}
	var claims map[string]any
	if err := json.Unmarshal(raw, &claims); err != nil {
		c.Fail("Malformed token", http.StatusUnauthorized)
		return
	}
	if exp, ok := claims["exp"].(float64); ok {
		if s.now().Unix() > int64(exp) {
			c.Fail("Token expired", http.StatusUnauthorized)
			return
		}
	}
	c.Success(claims)
}
