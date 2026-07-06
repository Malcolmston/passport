// Package jwtbearer implements the JWT Bearer authorization grant of RFC 7523
// ("JSON Web Token (JWT) Profile for OAuth 2.0 Client Authentication and
// Authorization Grants") for the passport port. It is the standard-library
// counterpart to the Node passport-oauth2-jwt-bearer and @node-oauth JWT bearer
// implementations, letting a client authenticate by presenting a signed JWT
// assertion instead of a username and password.
//
// Use this strategy on a token or resource endpoint that must accept RFC 7523
// bearer assertions: server-to-server flows where one service proves its
// identity with a JWT signed by its own key, and federated scenarios where an
// external identity provider issues assertions that your service accepts. It
// fits an OAuth 2.0 token endpoint receiving grant_type
// urn:ietf:params:oauth:grant-type:jwt-bearer (exported as GrantType), and it
// is the natural choice when credentials are asymmetric keys published as a
// JWKS rather than shared secrets.
//
// The flow reads the assertion from the POST form field named by Options.Field
// (defaulting to "assertion", per RFC 7521/7523), falling back to the same
// query parameter for convenience; a missing assertion fails with 401. The
// assertion is then verified and, on success, the verified jwt.Claims become
// the authenticated user available through passport.User(r). A failed
// verification is reported as the OAuth "invalid_grant" error with a 401
// status. The companion grant_type field that a spec-compliant client also
// sends is not required by this strategy, which keys solely on the assertion.
//
// Verification supports two modes and JWKSURL takes precedence. When
// Options.JWKSURL is set, assertions are verified against the issuer's
// published asymmetric keys (RS256/ES256), with Options.Algorithms optionally
// restricting the accepted "alg" values — the arrangement most production
// deployments need, since the issuer holds the private key and rotates it
// behind the JWKS endpoint. When JWKSURL is empty, Options.Secret is used to
// verify HS256 assertions with a symmetric shared secret, which is convenient
// for tests and tightly coupled internal services.
//
// Parity with Passport.js: like the Node jwt-bearer strategies, this validates
// an inbound JWT assertion against a configured key source and exposes the
// verified claims to the application, implementing the RFC 7523 grant on top of
// the same JWT verification primitives used by the jwt strategy in this module.
// The Strategy's registered name is "jwt-bearer".
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
