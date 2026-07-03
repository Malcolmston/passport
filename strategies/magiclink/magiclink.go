// Package magiclink implements passwordless "magic link" authentication. A
// signed, time-limited token is delivered to the user (typically by email) and
// presented back in the "?token=" query parameter. The token embeds the user's
// email and an expiry, protected by an HMAC-SHA256 signature.
//
// Token format:
//
//	base64url(payload) + "." + hex(HMAC-SHA256(payload))
//	payload = "email|expiryUnix"
package magiclink

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/malcolmston/passport"
)

// Sign builds a magic-link token for email that expires at exp.
func Sign(secret []byte, email string, exp time.Time) string {
	payload := email + "|" + strconv.FormatInt(exp.Unix(), 10)
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(payload))
	sig := hex.EncodeToString(mac.Sum(nil))
	return base64.RawURLEncoding.EncodeToString([]byte(payload)) + "." + sig
}

// Options configures the magiclink Strategy.
type Options struct {
	// Secret is the HMAC key used to sign and verify tokens.
	Secret []byte
	// Param names the query parameter carrying the token. Defaults to "token".
	Param string
	// Now returns the current time; defaults to time.Now. Injected for tests.
	Now func() time.Time
}

// Strategy authenticates requests presenting a valid, unexpired magic link.
type Strategy struct {
	secret []byte
	param  string
	now    func() time.Time
}

// New creates a magiclink Strategy.
func New(opts Options) *Strategy {
	param := opts.Param
	if param == "" {
		param = "token"
	}
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	return &Strategy{secret: opts.Secret, param: param, now: now}
}

// Name returns "magic-link".
func (s *Strategy) Name() string { return "magic-link" }

// Authenticate implements passport.Strategy.
func (s *Strategy) Authenticate(c *passport.Context, r *http.Request) {
	token := r.URL.Query().Get(s.param)
	if token == "" {
		c.Fail("Missing token", http.StatusUnauthorized)
		return
	}
	dot := strings.LastIndexByte(token, '.')
	if dot < 0 {
		c.Fail("Malformed token", http.StatusUnauthorized)
		return
	}
	rawPayload, sig := token[:dot], token[dot+1:]
	payload, err := base64.RawURLEncoding.DecodeString(rawPayload)
	if err != nil {
		c.Fail("Malformed token", http.StatusUnauthorized)
		return
	}

	mac := hmac.New(sha256.New, s.secret)
	mac.Write(payload)
	expected := hex.EncodeToString(mac.Sum(nil))
	if !hmac.Equal([]byte(sig), []byte(expected)) {
		c.Fail("Invalid signature", http.StatusUnauthorized)
		return
	}

	parts := strings.SplitN(string(payload), "|", 2)
	if len(parts) != 2 {
		c.Fail("Malformed token", http.StatusUnauthorized)
		return
	}
	email := parts[0]
	exp, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil {
		c.Fail("Malformed token", http.StatusUnauthorized)
		return
	}
	if s.now().Unix() > exp {
		c.Fail("Token expired", http.StatusUnauthorized)
		return
	}
	c.Success(email)
}
