// Package openidconnect implements an OpenID Connect (OIDC) authentication
// strategy layered on top of the OAuth 2.0 authorization-code flow.
//
// With no ?code in the request it redirects the user agent to the provider's
// authorization endpoint (with a scope that includes "openid"). When the
// provider redirects back with ?code, it exchanges the code at the token
// endpoint, verifies the returned id_token, and reports the token's claims as
// the authenticated user.
//
// id_token verification supports both modes real providers use:
//
//   - RS256/ES256 via a JWKS endpoint (Google, Auth0, Okta, Azure AD, ...):
//     set Config.JWKSURL (and optionally Config.Algorithms). Keys are fetched
//     from the endpoint and cached, refreshing on key rotation. This is the
//     production path.
//   - HS256 with a shared secret (Config.JWKSecret) via strategies/jwt: handy
//     for tests and symmetric-key setups.
//
// When JWKSURL is set it takes precedence; otherwise the HS256 path is used.
package openidconnect

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/malcolmston/passport"
	"github.com/malcolmston/passport/strategies/jwks"
	"github.com/malcolmston/passport/strategies/jwt"
)

// Config holds the OIDC client configuration.
type Config struct {
	Issuer       string
	ClientID     string
	ClientSecret string
	RedirectURL  string

	AuthURL  string
	TokenURL string

	// JWKSURL is the provider's JWKS endpoint. When set, id_tokens are verified
	// with the asymmetric keys (RS256/ES256/PS256) published there, which is
	// how real OIDC providers sign them. Takes precedence over JWKSecret.
	JWKSURL string

	// Algorithms restricts accepted id_token "alg" values when using JWKSURL
	// (e.g. {"RS256"}). Empty accepts any supported asymmetric algorithm.
	Algorithms []string

	// JWKSecret is the HS256 key used to verify the id_token when JWKSURL is
	// not configured. Handy for tests and symmetric-key deployments.
	JWKSecret []byte

	// Scopes are requested in addition to "openid" (always included).
	Scopes []string

	// HTTPClient is used for the token exchange. When nil, http.DefaultClient
	// is used. Injectable for tests.
	HTTPClient *http.Client
}

// VerifyFunc maps verified id_token claims to an application user. When nil, the
// claims themselves are used as the user. Returning a nil user (nil error) is an
// authentication failure.
type VerifyFunc func(claims jwt.Claims) (user any, err error)

// Strategy is an OpenID Connect authorization-code strategy.
type Strategy struct {
	cfg    Config
	verify VerifyFunc

	// jwksVerifier is set when cfg.JWKSURL is configured; it caches the
	// provider's signing keys across requests.
	jwksVerifier *jwks.Strategy
}

// New creates an OIDC Strategy. verify may be nil, in which case the id_token
// claims are used directly as the authenticated user.
func New(cfg Config, verify VerifyFunc) *Strategy {
	s := &Strategy{cfg: cfg, verify: verify}
	if cfg.JWKSURL != "" {
		s.jwksVerifier = jwks.New(jwks.Options{
			JWKSURL:    cfg.JWKSURL,
			Algorithms: cfg.Algorithms,
		}, nil)
	}
	return s
}

// Name returns "openidconnect".
func (s *Strategy) Name() string { return "openidconnect" }

func (s *Strategy) httpClient() *http.Client {
	if s.cfg.HTTPClient != nil {
		return s.cfg.HTTPClient
	}
	return http.DefaultClient
}

func (s *Strategy) scope() string {
	scopes := []string{"openid"}
	for _, sc := range s.cfg.Scopes {
		if sc != "openid" {
			scopes = append(scopes, sc)
		}
	}
	return strings.Join(scopes, " ")
}

// AuthCodeURL builds the authorization endpoint URL for the given state.
func (s *Strategy) AuthCodeURL(state string) string {
	v := url.Values{}
	v.Set("client_id", s.cfg.ClientID)
	v.Set("redirect_uri", s.cfg.RedirectURL)
	v.Set("response_type", "code")
	v.Set("scope", s.scope())
	if state != "" {
		v.Set("state", state)
	}
	sep := "?"
	if strings.Contains(s.cfg.AuthURL, "?") {
		sep = "&"
	}
	return s.cfg.AuthURL + sep + v.Encode()
}

// tokenResponse is the token endpoint reply; id_token carries the OIDC claims.
type tokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	IDToken     string `json:"id_token"`
	ExpiresIn   int    `json:"expires_in"`
}

// Exchange trades an authorization code for a token response.
func (s *Strategy) Exchange(ctx context.Context, code string) (*tokenResponse, error) {
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", s.cfg.RedirectURL)
	form.Set("client_id", s.cfg.ClientID)
	form.Set("client_secret", s.cfg.ClientSecret)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.cfg.TokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := s.httpClient().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("openidconnect: token endpoint returned %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var tr tokenResponse
	if err := json.Unmarshal(body, &tr); err != nil {
		return nil, fmt.Errorf("openidconnect: decoding token response: %w", err)
	}
	if tr.IDToken == "" {
		return nil, errors.New("openidconnect: token response has no id_token")
	}
	return &tr, nil
}

// verifyIDToken validates the id_token signature and time claims, returning its
// claims. It uses the JWKS endpoint (RS256/ES256) when configured, otherwise
// the HS256 shared secret.
func (s *Strategy) verifyIDToken(idToken string) (jwt.Claims, error) {
	if s.jwksVerifier != nil {
		claims, err := s.jwksVerifier.VerifyToken(idToken)
		if err != nil {
			return nil, err
		}
		return jwt.Claims(claims), nil
	}
	parser := jwt.New(s.cfg.JWKSecret, nil)
	return parser.Parse(idToken)
}

// Authenticate implements passport.Strategy.
func (s *Strategy) Authenticate(c *passport.Context, r *http.Request) {
	q := r.URL.Query()
	code := q.Get("code")
	if code == "" {
		c.Redirect(s.AuthCodeURL(q.Get("state")), http.StatusFound)
		return
	}

	tr, err := s.Exchange(r.Context(), code)
	if err != nil {
		c.Error(err)
		return
	}

	// Verify the id_token: RS256/ES256 via JWKS when configured, else HS256.
	claims, err := s.verifyIDToken(tr.IDToken)
	if err != nil {
		c.Fail("invalid_token", http.StatusUnauthorized)
		return
	}
	// Validate the issuer when configured.
	if s.cfg.Issuer != "" {
		if iss, _ := claims["iss"].(string); iss != s.cfg.Issuer {
			c.Fail("invalid_token", http.StatusUnauthorized)
			return
		}
	}

	if s.verify != nil {
		user, err := s.verify(claims)
		if err != nil {
			c.Error(err)
			return
		}
		if user == nil {
			c.Fail("", http.StatusUnauthorized)
			return
		}
		c.Success(user)
		return
	}
	c.Success(claims)
}
