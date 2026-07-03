// Package googleidtoken verifies a Google-style OpenID Connect id_token
// presented directly by the client (for example, from Google Sign-In's
// credential response), rather than running the full redirect flow.
//
// The token is read from an "id_token" query parameter or form field, its
// signature and expiry are verified, and its audience is checked against the
// configured client id. On success the token claims become the authenticated
// user.
//
// SIMPLIFIED: real Google id_tokens are signed with Google's rotating RS256
// keys published at a JWKS endpoint. This implementation verifies HS256 tokens
// with a shared secret via strategies/jwt so the strategy is exercisable with
// the standard library alone. Everything else (audience check, expiry check,
// claim extraction) mirrors real usage.
package googleidtoken

import (
	"net/http"

	"github.com/malcolmston/passport"
	"github.com/malcolmston/passport/strategies/jwt"
)

// Options configures the strategy.
type Options struct {
	// Secret is the HS256 key used to verify the id_token (simplified; real
	// Google uses RS256).
	Secret []byte
	// Audience, when non-empty, must equal the token's "aud" claim (your
	// Google OAuth client id).
	Audience string
}

// Strategy verifies a Google-style id_token.
type Strategy struct {
	opts Options
}

// New creates a Strategy from opts.
func New(opts Options) *Strategy { return &Strategy{opts: opts} }

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

	parser := jwt.New(s.opts.Secret, nil)
	claims, err := parser.Parse(token) // verifies signature and exp/nbf
	if err != nil {
		c.Fail("invalid_token", http.StatusUnauthorized)
		return
	}
	if s.opts.Audience != "" {
		if aud, _ := claims["aud"].(string); aud != s.opts.Audience {
			c.Fail("invalid_audience", http.StatusUnauthorized)
			return
		}
	}
	c.Success(claims)
}
