// Package jwt implements a JSON Web Token authentication strategy, a Go port of
// the Node passport-jwt strategy for the common HMAC-SHA256 (HS256) case. It
// verifies a token's signature and standard time claims (exp, nbf) using only
// the standard library, then hands the decoded claims to a user-supplied
// VerifyFunc that maps them to an application user.
//
// Use this strategy for stateless bearer authentication of APIs, where the
// client obtains a signed JWT (from a login endpoint or an identity provider
// that shares a symmetric secret with you) and presents it on subsequent
// requests. Because the token carries its own claims and is self-verifying, no
// server-side session store is required: the same secret that signs a token
// verifies it. The Sign helper is provided as a small convenience for issuing
// HS256 tokens in tests and simple issuers.
//
// The flow reads the token from the "Authorization: Bearer <jwt>" header by
// default, or from wherever Strategy.Extractor says — the FromHeader,
// FromURLQueryParameter, FromBodyField, FromAuthHeaderWithScheme and
// FromExtractors constructors mirror passport-jwt's ExtractJwt helpers. A
// missing token fails with 401 and a "WWW-Authenticate: Bearer" challenge. The
// token is then parsed by Parse, which splits the compact serialization,
// verifies that the header's "alg" is HS256, recomputes the HMAC-SHA256
// signature over "header.payload" with Strategy.Secret, and compares it against
// the presented signature in constant time (crypto/hmac). It then checks the
// numeric "exp" and "nbf" claims against the current time, honoring
// Strategy.Leeway to tolerate small clock skew between issuer and verifier.
// Strategy.RequireExpiry additionally rejects a token that carries no "exp" at
// all, and Strategy.Issuer and Strategy.Audience — passport-jwt's issuer and
// audience options — pin the "iss" and "aud" claims when set. Audience matters
// as soon as one issuer serves several services: without it a token minted for
// any of them is accepted by all of them. Verified claims are passed to
// VerifyFunc; a non-nil user authenticates the request while a nil user
// rejects it.
//
// Security semantics matter here. The strategy accepts HS256 and only HS256:
// any other "alg" value — including the notorious "none" and asymmetric
// algorithms like RS256 — is rejected with ErrAlgorithm. This closes the
// classic JWT algorithm-confusion attack in which an attacker swaps a token's
// algorithm to trick a verifier into treating a public key (or no key) as the
// HMAC secret. Signature comparison is constant-time to avoid timing oracles,
// and the exported sentinels ErrMalformed, ErrSignature, ErrExpired, ErrNotYet,
// ErrAlgorithm, and ErrNoToken let callers distinguish failure modes. On any
// verification failure the Authenticate method responds 401 with the header
// WWW-Authenticate: Bearer error="invalid_token".
//
// Parity with Passport.js: this mirrors passport-jwt's model of extracting a
// bearer token, verifying it, and invoking an application callback with the
// decoded payload, restricted to the symmetric-key (HS256) profile that the
// standard library can implement without external dependencies. VerifyFunc
// corresponds to the Node verify(payload, done) callback, Claims is the decoded
// payload with a Subject helper for the "sub" claim, and the fromAuthHeaderAsBearerToken
// extractor is the fixed default here. The Strategy's registered name is "jwt".
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

// Issuer returns the "iss" claim as a string, if present.
func (c Claims) Issuer() string { s, _ := c["iss"].(string); return s }

// Audience returns the "aud" claim as a slice. RFC 7519 permits "aud" to be
// either a single string or an array of strings, and both forms are normalized
// to a slice here; any other JSON type yields nil.
func (c Claims) Audience() []string {
	switch v := c["aud"].(type) {
	case string:
		return []string{v}
	case []any:
		out := make([]string, 0, len(v))
		for _, a := range v {
			if s, ok := a.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

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
	// ErrIssuer indicates the token's iss claim did not match Strategy.Issuer.
	ErrIssuer = errors.New("jwt: unexpected issuer")
	// ErrAudience indicates the token's aud claim did not include
	// Strategy.Audience.
	ErrAudience = errors.New("jwt: unexpected audience")
)

// Extractor pulls the compact JWT out of a request, returning "" when the
// request carries none. It corresponds to passport-jwt's jwtFromRequest option.
type Extractor func(r *http.Request) string

// FromAuthHeaderAsBearerToken returns an Extractor that reads the token from
// the "Authorization: Bearer <jwt>" header. It is the default and mirrors
// passport-jwt's ExtractJwt.fromAuthHeaderAsBearerToken().
func FromAuthHeaderAsBearerToken() Extractor {
	return func(r *http.Request) string {
		h := r.Header.Get("Authorization")
		if len(h) > 7 && strings.EqualFold(h[:7], "bearer ") {
			return strings.TrimSpace(h[7:])
		}
		return ""
	}
}

// FromAuthHeaderWithScheme returns an Extractor that reads the token from the
// Authorization header using an arbitrary scheme name, compared
// case-insensitively. It mirrors ExtractJwt.fromAuthHeaderWithScheme(scheme).
func FromAuthHeaderWithScheme(scheme string) Extractor {
	prefix := scheme + " "
	return func(r *http.Request) string {
		h := r.Header.Get("Authorization")
		if len(h) > len(prefix) && strings.EqualFold(h[:len(prefix)], prefix) {
			return strings.TrimSpace(h[len(prefix):])
		}
		return ""
	}
}

// FromHeader returns an Extractor that reads the token from a named header,
// mirroring ExtractJwt.fromHeader(name).
func FromHeader(name string) Extractor {
	return func(r *http.Request) string { return strings.TrimSpace(r.Header.Get(name)) }
}

// FromURLQueryParameter returns an Extractor that reads the token from a query
// parameter, mirroring ExtractJwt.fromUrlQueryParameter(name).
//
// Prefer a header. Query strings are routinely written to access logs, kept in
// browser history, and forwarded in the Referer header, so a token placed there
// tends to outlive the request that carried it.
func FromURLQueryParameter(name string) Extractor {
	return func(r *http.Request) string { return strings.TrimSpace(r.URL.Query().Get(name)) }
}

// FromBodyField returns an Extractor that reads the token from a form field,
// mirroring ExtractJwt.fromBodyField(name).
func FromBodyField(name string) Extractor {
	return func(r *http.Request) string {
		_ = r.ParseForm()
		return strings.TrimSpace(r.PostFormValue(name))
	}
}

// FromExtractors returns an Extractor that tries each of the given extractors
// in order and yields the first non-empty token, mirroring
// ExtractJwt.fromExtractors([...]).
func FromExtractors(extractors ...Extractor) Extractor {
	return func(r *http.Request) string {
		for _, e := range extractors {
			if e == nil {
				continue
			}
			if tok := e(r); tok != "" {
				return tok
			}
		}
		return ""
	}
}

// Strategy authenticates requests carrying a signed JWT.
type Strategy struct {
	// Secret is the HMAC signing key used to verify the token.
	Secret []byte
	// Leeway allows a small clock skew when checking exp/nbf (default 0).
	Leeway time.Duration
	// Issuer, when non-empty, must equal the token's "iss" claim. It
	// corresponds to passport-jwt's issuer option.
	Issuer string
	// Audience, when non-empty, must appear in the token's "aud" claim, which
	// JWT allows to be either a string or an array of strings. It corresponds
	// to passport-jwt's audience option.
	//
	// Set this whenever the issuer mints tokens for more than one service:
	// without it, a token any other audience received is equally acceptable
	// here, so a token handed to a less-trusted service can be replayed
	// against this one.
	Audience string
	// RequireExpiry rejects a token that carries no "exp" claim. A JWT without
	// an expiry is valid forever and cannot be revoked, so require one unless
	// something else bounds the token's lifetime.
	RequireExpiry bool
	// Extractor locates the token on the request. Defaults to
	// FromAuthHeaderAsBearerToken().
	Extractor Extractor

	verify VerifyFunc
}

// New creates a JWT strategy that verifies HS256 tokens with the given secret.
// The token is read from the Authorization: Bearer header; set Extractor to
// read it from somewhere else.
func New(secret []byte, verify VerifyFunc) *Strategy {
	return &Strategy{Secret: secret, verify: verify}
}

// Name returns "jwt".
func (s *Strategy) Name() string { return "jwt" }

// Authenticate implements passport.Strategy.
func (s *Strategy) Authenticate(c *passport.Context, r *http.Request) {
	token := s.extractor()(r)
	if token == "" {
		c.Fail("Bearer", http.StatusUnauthorized)
		return
	}
	claims, err := s.Parse(token)
	if err != nil {
		switch {
		case errors.Is(err, ErrExpired), errors.Is(err, ErrSignature),
			errors.Is(err, ErrNotYet), errors.Is(err, ErrMalformed),
			errors.Is(err, ErrAlgorithm), errors.Is(err, ErrIssuer),
			errors.Is(err, ErrAudience):
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
	exp, hasExp := numericClaim(claims, "exp")
	if hasExp {
		if now.Add(-s.Leeway).After(time.Unix(int64(exp), 0)) {
			return nil, ErrExpired
		}
	} else if s.RequireExpiry {
		return nil, ErrExpired
	}
	if nbf, ok := numericClaim(claims, "nbf"); ok {
		if now.Add(s.Leeway).Before(time.Unix(int64(nbf), 0)) {
			return nil, ErrNotYet
		}
	}
	if s.Issuer != "" && claims.Issuer() != s.Issuer {
		return nil, ErrIssuer
	}
	if s.Audience != "" && !containsString(claims.Audience(), s.Audience) {
		return nil, ErrAudience
	}
	return claims, nil
}

func containsString(ss []string, want string) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
	}
	return false
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

// extractor returns the configured Extractor, or the bearer-header default.
func (s *Strategy) extractor() Extractor {
	if s.Extractor != nil {
		return s.Extractor
	}
	return FromAuthHeaderAsBearerToken()
}
