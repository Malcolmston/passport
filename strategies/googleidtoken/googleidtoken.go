// Package googleidtoken verifies a Google-style OpenID Connect id_token that is
// presented directly by the client — for example the JWT credential returned by
// Google Sign-In or the Google Identity Services button — rather than running
// the full OAuth 2.0 authorization-code redirect flow. It is the Go analogue of
// Node's passport-google-id-token strategy and of google-auth-library's
// verifyIdToken helper, packaged as a passport.Strategy whose Name is
// "google-id-token".
//
// Use this strategy when the browser already holds a signed id_token and simply
// forwards it to your backend for validation, which is the common shape of
// modern client-side Google Sign-In. Because there is no code exchange, no
// client secret, redirect URI, or session round-trip to the provider is
// involved; the backend's entire job is to prove the token is authentic,
// unexpired, and intended for your application before trusting its claims.
//
// The token is read from an "id_token" query parameter first and, if absent,
// from an "id_token" POST form field. Its signature and time claims (exp/nbf)
// are verified, then — when configured — its issuer ("iss") and audience
// ("aud") claims are checked. On success the decoded jwt.Claims become the
// authenticated user; any failure results in a 401 with a short reason such as
// "invalid_token", "invalid_issuer", or "invalid_audience".
//
// Signature verification supports two modes. The real path is RS256 against
// Google's rotating public keys published as a JWKS: set Options.JWKSURL to
// GoogleCertsURL ("https://www.googleapis.com/oauth2/v3/certs") and the keys are
// fetched and cached (with automatic refetch on key rotation) by the underlying
// jwks strategy. The alternative is HS256 with a shared secret (Options.Secret),
// which lets the strategy be exercised with the standard library alone and is
// intended for tests. When JWKSURL is set it takes precedence over Secret.
//
// Pin both Options.Audience (your Google OAuth client id, matched against "aud")
// and Options.Issuer ("https://accounts.google.com" or "accounts.google.com")
// in production: the audience check is what stops a validly signed token minted
// for a different application from being accepted by yours. Aside from the
// client-presented token being read from the request body rather than obtained
// through a redirect, the audience/issuer pinning, expiry enforcement, and claim
// extraction mirror the guarantees of the Passport.js strategy it ports.
package googleidtoken

import (
	"net/http"

	"github.com/malcolmston/passport"
	"github.com/malcolmston/passport/strategies/jwks"
	"github.com/malcolmston/passport/strategies/jwt"
)

// GoogleCertsURL is Google's published JWKS (JWK Set) endpoint for id_token
// signing keys.
const GoogleCertsURL = "https://www.googleapis.com/oauth2/v3/certs"

// Options configures the strategy.
type Options struct {
	// JWKSURL is the JWKS endpoint used to verify RS256 id_tokens. For real
	// Google Sign-In this is GoogleCertsURL. Takes precedence over Secret.
	JWKSURL string
	// Secret is the HS256 key used to verify the id_token when JWKSURL is not
	// set (simplified; real Google uses RS256).
	Secret []byte
	// Audience, when non-empty, must equal the token's "aud" claim (your
	// Google OAuth client id).
	Audience string
	// Issuer, when non-empty, must equal the token's "iss" claim (Google uses
	// "https://accounts.google.com" or "accounts.google.com").
	Issuer string
}

// Strategy verifies a Google-style id_token.
type Strategy struct {
	opts     Options
	verifier *jwks.Strategy
}

// New creates a Strategy from opts.
func New(opts Options) *Strategy {
	s := &Strategy{opts: opts}
	if opts.JWKSURL != "" {
		s.verifier = jwks.New(jwks.Options{JWKSURL: opts.JWKSURL, Algorithms: []string{"RS256"}}, nil)
	}
	return s
}

// Name returns "google-id-token".
func (s *Strategy) Name() string { return "google-id-token" }

// Authenticate implements passport.Strategy. The id_token is read from the
// "id_token" query parameter or form field.
func (s *Strategy) Authenticate(c *passport.Context, r *http.Request) {
	token := r.URL.Query().Get("id_token")
	if token == "" {
		_ = r.ParseForm()
		token = r.PostFormValue("id_token")
	}
	if token == "" {
		c.Fail("missing id_token", http.StatusUnauthorized)
		return
	}

	claims, err := s.verify(token) // verifies signature and exp/nbf
	if err != nil {
		c.Fail("invalid_token", http.StatusUnauthorized)
		return
	}
	if s.opts.Issuer != "" {
		if iss, _ := claims["iss"].(string); iss != s.opts.Issuer {
			c.Fail("invalid_issuer", http.StatusUnauthorized)
			return
		}
	}
	if s.opts.Audience != "" {
		if aud, _ := claims["aud"].(string); aud != s.opts.Audience {
			c.Fail("invalid_audience", http.StatusUnauthorized)
			return
		}
	}
	c.Success(claims)
}

// verify checks the token signature and time claims via JWKS (RS256) when
// configured, otherwise via the HS256 shared secret.
func (s *Strategy) verify(token string) (jwt.Claims, error) {
	if s.verifier != nil {
		claims, err := s.verifier.VerifyToken(token)
		if err != nil {
			return nil, err
		}
		return jwt.Claims(claims), nil
	}
	return jwt.New(s.opts.Secret, nil).Parse(token)
}
