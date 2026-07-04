// Package jwtbearer implements the JWT Bearer authorization grant of RFC 7523
// ("JSON Web Token (JWT) Profile for OAuth 2.0 Client Authentication and
// Authorization Grants") for the passport port.
//
// The client presents a signed JWT assertion in the "assertion" form field
// (as specified by RFC 7521/7523). The assertion is verified and, on success,
// its claims become the authenticated user.
//
// Verification supports both an HS256 shared secret (Options.Secret) and, as a
// production deployment typically requires, the issuer's published asymmetric
// keys via a JWKS endpoint (Options.JWKSURL, RS256/ES256). When JWKSURL is set
// it takes precedence.
package jwtbearer

import (
	"net/http"

	"github.com/malcolmston/passport"
	"github.com/malcolmston/passport/strategies/jwks"
	"github.com/malcolmston/passport/strategies/jwt"
)

// GrantType is the RFC 7523 grant_type value for the JWT bearer grant.
const GrantType = "urn:ietf:params:oauth:grant-type:jwt-bearer"

// Options configures the strategy.
type Options struct {
	// JWKSURL is the issuer's JWKS endpoint used to verify RS256/ES256
	// assertions. Takes precedence over Secret.
	JWKSURL string
	// Algorithms restricts accepted assertion "alg" values when using JWKSURL.
	Algorithms []string
	// Secret is the HS256 key used to verify the assertion when JWKSURL is not
	// set.
	Secret []byte
	// Field is the form field carrying the assertion. Defaults to "assertion".
	Field string
}

// Strategy authenticates requests presenting a JWT bearer assertion.
type Strategy struct {
	secret   []byte
	field    string
	verifier *jwks.Strategy
}

// New creates a Strategy from opts.
func New(opts Options) *Strategy {
	field := opts.Field
	if field == "" {
		field = "assertion"
	}
	s := &Strategy{secret: opts.Secret, field: field}
	if opts.JWKSURL != "" {
		s.verifier = jwks.New(jwks.Options{JWKSURL: opts.JWKSURL, Algorithms: opts.Algorithms}, nil)
	}
	return s
}

// Name returns "jwt-bearer".
func (s *Strategy) Name() string { return "jwt-bearer" }

// Authenticate implements passport.Strategy.
func (s *Strategy) Authenticate(c *passport.Context, r *http.Request) {
	_ = r.ParseForm()
	assertion := r.PostFormValue(s.field)
	if assertion == "" {
		// Also accept it from the query for convenience.
		assertion = r.URL.Query().Get(s.field)
	}
	if assertion == "" {
		c.Fail("missing assertion", http.StatusUnauthorized)
		return
	}

	claims, err := s.verify(assertion)
	if err != nil {
		c.Fail("invalid_grant", http.StatusUnauthorized)
		return
	}
	c.Success(claims)
}

// verify checks the assertion via JWKS (RS256/ES256) when configured, else via
// the HS256 shared secret.
func (s *Strategy) verify(assertion string) (jwt.Claims, error) {
	if s.verifier != nil {
		claims, err := s.verifier.VerifyToken(assertion)
		if err != nil {
			return nil, err
		}
		return jwt.Claims(claims), nil
	}
	return jwt.New(s.secret, nil).Parse(assertion)
}
