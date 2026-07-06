// Package openidconnect implements an OpenID Connect (OIDC) authentication
// strategy layered on top of the OAuth 2.0 authorization-code flow. It ports
// passport-openidconnect from the Passport.js ecosystem and, like that module,
// is the shared base other OIDC provider presets are built on: Okta, OneLogin,
// Azure AD, Auth0, Salesforce and similar providers are just this strategy with
// their issuer, endpoints and JWKS URL filled in. Use it directly for any
// standards-compliant OIDC provider, or as the foundation for a new
// provider-specific preset.
//
// Reach for this strategy (rather than a plain OAuth2 preset) when you need the
// identity guarantees OIDC adds on top of OAuth 2.0: a signed id_token whose
// claims describe the authenticated end user, validated against a known issuer.
// A plain OAuth2 login proves the app obtained an access token; OIDC proves who
// the user is by cryptographically verifying the id_token, which is what you
// want for single sign-on and account linking.
//
// The flow has two legs. On a request with no ?code the strategy issues a 302
// redirect to the provider's authorization endpoint (Config.AuthURL), with a
// scope that always includes "openid" plus any extra Config.Scopes, the client
// ID, the redirect URI, response_type=code, and the caller-supplied state. The
// provider authenticates the user and redirects back to Config.RedirectURL with
// a ?code (and the same state, which the surrounding passport machinery should
// validate for CSRF protection). On that second request the strategy exchanges
// the code at Config.TokenURL for a token response, then verifies the returned
// id_token before trusting any of its contents. AuthCodeURL and Exchange are
// exported so callers can drive the two legs manually if they are not using the
// passport middleware.
//
// id_token verification supports both modes real providers use, and this is the
// security-critical part of the strategy:
//
//   - RS256/ES256/PS256 via a JWKS endpoint (Google, Auth0, Okta, Azure AD,
//     ...): set Config.JWKSURL (and optionally Config.Algorithms to pin the
//     accepted "alg" values). The provider's public signing keys are fetched
//     from the endpoint and cached across requests, refreshing automatically on
//     key rotation. This is the production path and is preferred.
//   - HS256 with a shared secret (Config.JWKSecret) via strategies/jwt: convenient
//     for tests and symmetric-key deployments, but only appropriate when the app
//     and issuer share a secret.
//
// When JWKSURL is set it takes precedence; otherwise the HS256 path is used.
// Verification checks the token signature and its time-based claims (exp/nbf via
// strategies/jwt); a bad signature or an expired token is reported as an
// authentication failure ("invalid_token", 401) rather than a hard error. When
// Config.Issuer is non-empty the token's "iss" claim must match it exactly, which
// defends against tokens minted by a different provider; a mismatch is likewise a
// 401 failure. Note that audience ("aud") checking against the client ID is not
// performed automatically here — enforce it in your VerifyFunc if your threat
// model requires it.
//
// On success the strategy reports the authenticated user. If a VerifyFunc was
// supplied it receives the verified claims and returns your application user;
// returning a nil user (with a nil error) is treated as an authentication
// failure, while a non-nil error surfaces as an internal error. If VerifyFunc is
// nil the raw jwt.Claims are used as the user. Parity note relative to the Node
// original: this implementation validates the id_token signature, expiry and
// issuer, but does not implement the full optional feature set of
// passport-openidconnect (nonce round-tripping, dynamic discovery of endpoints
// from the issuer's /.well-known/openid-configuration document, PKCE, or
// userinfo fetching) — endpoints are configured explicitly and the id_token
// claims stand in for the userinfo response.
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
	Issuer       string // OIDC issuer identifier, validated against the id_token "iss" claim
	ClientID     string // OAuth2 client (application) ID
	ClientSecret string // OAuth2 client (application) secret
	RedirectURL  string // URL the provider redirects back to after authorization

	AuthURL  string // provider authorization endpoint
	TokenURL string // provider token-exchange endpoint

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
