// Package jwtbearer implements the JWT Bearer authorization grant of RFC 7523
// ("JSON Web Token (JWT) Profile for OAuth 2.0 Client Authentication and
// Authorization Grants") for the passport port.
//
// The client presents a signed JWT assertion in the "assertion" form field
// (as specified by RFC 7521/7523). The assertion is verified and, on success,
// its claims become the authenticated user.
//
// SIMPLIFIED: the assertion is verified as an HS256 JWT with a shared secret
// via strategies/jwt. A production deployment typically verifies the
// assertion against the issuer's published (asymmetric) key.
package jwtbearer

import (
	"net/http"

	"github.com/malcolmston/passport"
	"github.com/malcolmston/passport/strategies/jwt"
)

// GrantType is the RFC 7523 grant_type value for the JWT bearer grant.
const GrantType = "urn:ietf:params:oauth:grant-type:jwt-bearer"

// Options configures the strategy.
type Options struct {
	// Secret is the HS256 key used to verify the assertion.
	Secret []byte
	// Field is the form field carrying the assertion. Defaults to "assertion".
	Field string
}

// Strategy authenticates requests presenting a JWT bearer assertion.
type Strategy struct {
	secret []byte
	field  string
}

// New creates a Strategy from opts.
func New(opts Options) *Strategy {
	field := opts.Field
	if field == "" {
		field = "assertion"
	}
	return &Strategy{secret: opts.Secret, field: field}
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

	parser := jwt.New(s.secret, nil)
	claims, err := parser.Parse(assertion)
	if err != nil {
		c.Fail("invalid_grant", http.StatusUnauthorized)
		return
	}
	c.Success(claims)
}
