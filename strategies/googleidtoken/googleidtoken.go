// Package googleidtoken verifies a Google-style OpenID Connect id_token
// presented directly by the client (for example, from Google Sign-In's
// credential response), rather than running the full redirect flow.
//
// The token is read from an "id_token" query parameter or form field, its
// signature and expiry are verified, and its audience is checked against the
// configured client id. On success the token claims become the authenticated
// user.
//
// Verification supports both signing modes:
//
//   - RS256 via Google's JWKS endpoint (the real path). Set Options.JWKSURL to
//     "https://www.googleapis.com/oauth2/v3/certs"; Google's rotating public
//     keys are fetched and cached automatically.
//   - HS256 with a shared secret (Options.Secret), which keeps the strategy
//     exercisable with the standard library alone (useful for tests).
//
// When JWKSURL is set it takes precedence. Everything else (audience check,
// expiry check, claim extraction) mirrors real usage.
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
