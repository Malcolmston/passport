// Package oauth2 implements a generic, standard-library-only OAuth 2.0
// authorization-code strategy for the passport port. It is the shared engine
// behind every concrete OAuth2 provider package in this module (github, google,
// kakao, line, microsoft, notion, and the rest): each of those is a thin
// wrapper that presets this package's endpoints and default scopes, so the
// redirect, token-exchange, and userinfo logic lives here in exactly one place.
// It ports passport-oauth2, the Node base strategy that the passport-* provider
// strategies extend, and is therefore the core abstraction other providers
// build on rather than a standalone provider.
//
// Reach for this package directly when you need to talk to an OAuth2 provider
// that has no dedicated wrapper: supply the provider's authorization, token,
// and (optionally) userinfo URLs in a Config together with your client
// credentials and requested Scopes, and you get a ready passport.Strategy. When
// a wrapper does exist, prefer it — it fills in the URLs and sensible default
// scopes for you and still returns a *Strategy from this package, so everything
// documented here applies unchanged.
//
// The flow is the standard three-step authorization-code grant. A request that
// arrives without a "code" query parameter is treated as the start of login:
// Authenticate builds the provider authorization URL with AuthCodeURL and
// redirects the browser to it. The provider authenticates the user and redirects
// back to RedirectURL with a "code" (and the "state" that was passed through).
// On that second request Exchange POSTs the code to TokenURL to obtain an access
// token, FetchUserInfo GETs UserInfoURL with that token, and the decoded profile
// is handed to your VerifyFunc.
//
// Several semantics are worth knowing. Scopes are space-joined into the
// authorization request per the OAuth2 spec. The "state" parameter is passed
// through opaquely for CSRF protection but is neither generated nor validated
// here — the surrounding passport middleware owns that — and this package does
// not implement PKCE. UserInfoURL may be left empty for providers that expose no
// userinfo endpoint (Apple, Stripe), in which case FetchUserInfo returns an
// empty map and the Profile carries only the access token; extractID otherwise
// makes a best-effort attempt to populate Profile.ID from the common "id",
// "sub", "user_id", "uuid", or "login" fields. A non-nil HTTPClient in Config is
// used for every outbound call, which is how tests inject a stub transport.
//
// The VerifyFunc contract mirrors Passport.js: return a non-nil user to
// establish the session, return a nil user with a nil error to reject the login
// (reported as an HTTP 401 failure), and return a non-nil error for an internal
// failure (reported via Context.Error). Compared with the Node passport-oauth2,
// this port keeps the same redirect/callback shape and verify semantics but is
// deliberately smaller: it has no built-in state store, no PKCE, and no
// automatic token refresh, trading those extras for a dependency-free, easily
// testable core.
package oauth2

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
)

// Config holds the endpoints and client credentials for an OAuth2 provider.
type Config struct {
	ClientID     string // OAuth2 client (application) ID
	ClientSecret string // OAuth2 client (application) secret
	RedirectURL  string // URL the provider redirects back to after authorization

	AuthURL     string // provider authorization endpoint
	TokenURL    string // provider token-exchange endpoint
	UserInfoURL string // provider endpoint returning the authenticated user's profile

	Scopes []string // OAuth2 scopes requested during authorization

	// HTTPClient is used for the token exchange and userinfo requests. When
	// nil, http.DefaultClient is used. Injectable for tests.
	HTTPClient *http.Client
}

// Profile is the normalized identity produced by a successful authentication.
type Profile struct {
	Provider    string         // name of the provider that issued the profile
	ID          string         // provider-specific unique user identifier
	Raw         map[string]any // raw decoded userinfo response from the provider
	AccessToken string         // access token obtained during the exchange
}

// VerifyFunc maps a fetched Profile to an application user. Returning a nil
// user (with nil error) is treated as an authentication failure; a non-nil
// error is treated as an internal error.
type VerifyFunc func(p Profile) (user any, err error)

// Strategy is a generic OAuth2 authorization-code strategy.
type Strategy struct {
	name   string
	cfg    Config
	verify VerifyFunc
}

// Token is the parsed response from the token endpoint.
type Token struct {
	AccessToken  string `json:"access_token"`  // token used to authorize API requests
	TokenType    string `json:"token_type"`    // token type, typically "Bearer"
	RefreshToken string `json:"refresh_token"` // token used to obtain a new access token
	ExpiresIn    int    `json:"expires_in"`    // access-token lifetime in seconds
	Scope        string `json:"scope"`         // scopes granted with the token
}

// New creates a Strategy registered under name using cfg and verify.
func New(name string, cfg Config, verify VerifyFunc) *Strategy {
	return &Strategy{name: name, cfg: cfg, verify: verify}
}

// Compile-time proof that the shared base implements the root package's
// optional OAuth2Provider capability interface. Every concrete provider
// package (github, google, gitlab, discord, facebook, ...) returns a
// *Strategy, so they all satisfy it too.
var _ passport.OAuth2Provider = (*Strategy)(nil)

// Name returns the strategy name.
func (s *Strategy) Name() string { return s.name }

// AuthURL returns the provider's configured authorization endpoint.
func (s *Strategy) AuthURL() string { return s.cfg.AuthURL }

// TokenURL returns the provider's configured token endpoint.
func (s *Strategy) TokenURL() string { return s.cfg.TokenURL }

func (s *Strategy) httpClient() *http.Client {
	if s.cfg.HTTPClient != nil {
		return s.cfg.HTTPClient
	}
	return http.DefaultClient
}

// AuthCodeURL builds the provider authorization URL for the given state.
func (s *Strategy) AuthCodeURL(state string) string {
	v := url.Values{}
	v.Set("client_id", s.cfg.ClientID)
	v.Set("redirect_uri", s.cfg.RedirectURL)
	v.Set("response_type", "code")
	if len(s.cfg.Scopes) > 0 {
		v.Set("scope", strings.Join(s.cfg.Scopes, " "))
	}
	if state != "" {
		v.Set("state", state)
	}
	sep := "?"
	if strings.Contains(s.cfg.AuthURL, "?") {
		sep = "&"
	}
	return s.cfg.AuthURL + sep + v.Encode()
}

// Exchange trades an authorization code for a Token at the token endpoint.
func (s *Strategy) Exchange(ctx context.Context, code string) (*Token, error) {
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", s.cfg.RedirectURL)
	form.Set("client_id", s.cfg.ClientID)
	form.Set("client_secret", s.cfg.ClientSecret)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.cfg.TokenURL,
		strings.NewReader(form.Encode()))
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
		return nil, fmt.Errorf("oauth2: token endpoint returned %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var tok Token
	if err := json.Unmarshal(body, &tok); err != nil {
		return nil, fmt.Errorf("oauth2: decoding token response: %w", err)
	}
	if tok.AccessToken == "" {
		return nil, errors.New("oauth2: token endpoint returned no access_token")
	}
	return &tok, nil
}

// FetchUserInfo GETs the userinfo endpoint using the access token and decodes
// the JSON body into a generic map. When UserInfoURL is empty it returns an
// empty map (some providers, e.g. Apple/Stripe, expose no userinfo endpoint).
func (s *Strategy) FetchUserInfo(ctx context.Context, accessToken string) (map[string]any, error) {
	if s.cfg.UserInfoURL == "" {
		return map[string]any{}, nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.cfg.UserInfoURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
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
		return nil, fmt.Errorf("oauth2: userinfo endpoint returned %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	raw := map[string]any{}
	if len(body) > 0 {
		if err := json.Unmarshal(body, &raw); err != nil {
			return nil, fmt.Errorf("oauth2: decoding userinfo response: %w", err)
		}
	}
	return raw, nil
}

// Authenticate implements passport.Strategy. With no ?code= it redirects to the
// provider; with ?code= it performs the exchange, fetches the profile, and runs
// the VerifyFunc.
func (s *Strategy) Authenticate(c *passport.Context, r *http.Request) {
	q := r.URL.Query()
	code := q.Get("code")
	if code == "" {
		state := q.Get("state")
		c.Redirect(s.AuthCodeURL(state), http.StatusFound)
		return
	}

	ctx := r.Context()
	tok, err := s.Exchange(ctx, code)
	if err != nil {
		c.Error(err)
		return
	}

	raw, err := s.FetchUserInfo(ctx, tok.AccessToken)
	if err != nil {
		c.Error(err)
		return
	}

	profile := Profile{
		Provider:    s.name,
		ID:          extractID(raw),
		Raw:         raw,
		AccessToken: tok.AccessToken,
	}

	user, err := s.verify(profile)
	if err != nil {
		c.Error(err)
		return
	}
	if user == nil {
		c.Fail("", http.StatusUnauthorized)
		return
	}
	c.Success(user)
}

// extractID pulls a best-effort user id out of a userinfo payload, checking the
// common field names used across providers.
func extractID(raw map[string]any) string {
	for _, key := range []string{"id", "sub", "user_id", "uuid", "login"} {
		if v, ok := raw[key]; ok {
			switch t := v.(type) {
			case string:
				if t != "" {
					return t
				}
			case float64:
				return fmt.Sprintf("%.0f", t)
			case json.Number:
				return t.String()
			}
		}
	}
	return ""
}
