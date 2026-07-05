// Package jwt implements a JSON Web Token authentication strategy, a Go port of
// passport-jwt for the common HMAC-SHA256 (HS256) case. It verifies a token's
// signature and standard time claims (exp, nbf) using only the standard
// library, then hands the decoded claims to a user-supplied VerifyFunc.
package jwt

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/malcolmston/passport"
)

// Claims is the decoded JWT payload.
type Claims map[string]any

// Subject returns the "sub" claim as a string, if present.
func (c Claims) Subject() string { s, _ := c["sub"].(string); return s }

// VerifyFunc maps verified token claims to an application user. Return
// (nil, nil) to reject the token.
type VerifyFunc func(claims Claims) (user any, err error)

// Common verification errors.
var (
	// ErrMalformed indicates the token could not be parsed.
	ErrMalformed = errors.New("jwt: malformed token")
	// ErrSignature indicates the token signature did not verify.
	ErrSignature = errors.New("jwt: signature verification failed")
	// ErrExpired indicates the token's exp claim is in the past.
	ErrExpired = errors.New("jwt: token expired")
	// ErrNotYet indicates the token's nbf claim is in the future.
	ErrNotYet = errors.New("jwt: token not valid yet")
	// ErrAlgorithm indicates the token uses an unexpected signing algorithm.
	ErrAlgorithm = errors.New("jwt: unexpected signing algorithm")
	// ErrNoToken indicates no token was supplied on the request.
	ErrNoToken = errors.New("jwt: no token supplied")
)

// Strategy authenticates requests carrying a signed JWT.
type Strategy struct {
	// Secret is the HMAC signing key used to verify the token.
	Secret []byte
	// Leeway allows a small clock skew when checking exp/nbf (default 0).
	Leeway time.Duration

	verify VerifyFunc
}

// New creates a JWT strategy that verifies HS256 tokens with the given secret.
func New(secret []byte, verify VerifyFunc) *Strategy {
	return &Strategy{Secret: secret, verify: verify}
}

// Name returns "jwt".
func (s *Strategy) Name() string { return "jwt" }

// Authenticate implements passport.Strategy.
func (s *Strategy) Authenticate(c *passport.Context, r *http.Request) {
	token := extractToken(r)
	if token == "" {
		c.Fail("Bearer", http.StatusUnauthorized)
		return
	}
	claims, err := s.Parse(token)
	if err != nil {
		if errors.Is(err, ErrExpired) || errors.Is(err, ErrSignature) || errors.Is(err, ErrNotYet) || errors.Is(err, ErrMalformed) || errors.Is(err, ErrAlgorithm) {
			c.Fail("Bearer error=\"invalid_token\"", http.StatusUnauthorized)
			return
		}
		c.Error(err)
		return
	}
	user, err := s.verify(claims)
	if err != nil {
		c.Error(err)
		return
	}
	if user == nil {
		c.Fail("Bearer error=\"invalid_token\"", http.StatusUnauthorized)
		return
	}
	c.Success(user)
}

// Parse verifies a token's signature and time claims and returns its claims.
func (s *Strategy) Parse(token string) (Claims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, ErrMalformed
	}
	headerJSON, err := decodeSegment(parts[0])
	if err != nil {
		return nil, ErrMalformed
	}
	var header struct {
		Alg string `json:"alg"`
		Typ string `json:"typ"`
	}
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		return nil, ErrMalformed
	}
	if header.Alg != "HS256" {
		return nil, ErrAlgorithm
	}

	// Verify the signature over "header.payload".
	signingInput := parts[0] + "." + parts[1]
	expected := sign(s.Secret, signingInput)
	got, err := decodeSegment(parts[2])
	if err != nil {
		return nil, ErrMalformed
	}
	if !hmac.Equal(expected, got) {
		return nil, ErrSignature
	}

	payloadJSON, err := decodeSegment(parts[1])
	if err != nil {
		return nil, ErrMalformed
	}
	var claims Claims
	if err := json.Unmarshal(payloadJSON, &claims); err != nil {
		return nil, ErrMalformed
	}

	now := time.Now()
	if exp, ok := numericClaim(claims, "exp"); ok {
		if now.Add(-s.Leeway).After(time.Unix(int64(exp), 0)) {
			return nil, ErrExpired
		}
	}
	if nbf, ok := numericClaim(claims, "nbf"); ok {
		if now.Add(s.Leeway).Before(time.Unix(int64(nbf), 0)) {
			return nil, ErrNotYet
		}
	}
	return claims, nil
}

// Sign creates an HS256 JWT for the given claims and secret. It is a small
// convenience for tests and token issuance.
func Sign(secret []byte, claims Claims) (string, error) {
	header := map[string]string{"alg": "HS256", "typ": "JWT"}
	h, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	p, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	signingInput := encodeSegment(h) + "." + encodeSegment(p)
	sig := sign(secret, signingInput)
	return signingInput + "." + encodeSegment(sig), nil
}

func sign(secret []byte, input string) []byte {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(input))
	return mac.Sum(nil)
}

func encodeSegment(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

func decodeSegment(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(s)
}

func numericClaim(c Claims, key string) (float64, bool) {
	switch v := c[key].(type) {
	case float64:
		return v, true
	case int64:
		return float64(v), true
	case int:
		return float64(v), true
	default:
		return 0, false
	}
}

func extractToken(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if len(h) > 7 && strings.EqualFold(h[:7], "bearer ") {
		return strings.TrimSpace(h[7:])
	}
	return ""
}
