// Package signedtoken implements self-contained HMAC-signed token
// authentication. A token carries a JSON claims object signed with HMAC-SHA256,
// so it can be verified without any server-side state. The token is read from
// the "Authorization: Bearer <token>" header.
//
// Token format:
//
//	base64url(JSON claims) + "." + hex(HMAC-SHA256(base64url(JSON claims)))
//
// If the claims include a numeric "exp" field (Unix seconds) it is enforced.
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
