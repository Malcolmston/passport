// This file wires the jwks verifier into a passport.Strategy so OpenID Connect
// providers (Google, Auth0, Okta, Azure AD, Cognito, ...) that sign id_tokens
// with rotating RS256/ES256 keys can be authenticated directly against their
// published JWKS endpoint.
package jwks

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/malcolmston/passport"
)

// VerifyFunc maps verified token claims to an application user. Return
// (nil, nil) to reject the token.
type VerifyFunc func(claims Claims) (user any, err error)

// Options configures a Strategy.
type Options struct {
	// JWKSURL is the provider's JWKS endpoint (e.g.
	// "https://www.googleapis.com/oauth2/v3/certs"). Keys fetched from it are
	// cached and refreshed when an unknown kid is seen. Either JWKSURL, Set, or
	// Resolve must be provided.
	JWKSURL string
	// Set is a static, pre-loaded key set (alternative to JWKSURL).
	Set *Set
	// Resolve is a fully custom key resolver (alternative to JWKSURL/Set).
	Resolve KeyResolver

	// Issuer, when non-empty, must equal the token's "iss" claim.
	Issuer string
	// Audience, when non-empty, must be present in the token's "aud" claim.
	Audience string
	// Algorithms restricts the accepted "alg" header values (e.g.
	// {"RS256"}). Empty means any supported asymmetric algorithm; HS* is never
	// accepted here to avoid key-confusion attacks.
	Algorithms []string

	// CacheTTL bounds how long fetched keys are reused before a forced refresh
	// (default 1 hour).
	CacheTTL time.Duration
	// HTTPClient fetches the JWKS document (default http.DefaultClient).
	HTTPClient *http.Client
	// TokenFromParam, when true, reads the token from the "id_token" or
	// "access_token" query/form field instead of the Authorization: Bearer
	// header (the default).
	TokenFromParam bool
}

// Strategy authenticates a request carrying a JWT verified against a JWKS.
type Strategy struct {
	opts   Options
	verify VerifyFunc

	mu        sync.Mutex
	cached    *Set
	fetchedAt time.Time
}

// New creates a JWKS-backed strategy. verify may be nil, in which case the raw
// Claims become the authenticated user.
func New(opts Options, verify VerifyFunc) *Strategy {
	if opts.CacheTTL == 0 {
		opts.CacheTTL = time.Hour
	}
	if opts.HTTPClient == nil {
		opts.HTTPClient = http.DefaultClient
	}
	return &Strategy{opts: opts, verify: verify}
}

// Name returns "jwks".
func (s *Strategy) Name() string { return "jwks" }

// Authenticate implements passport.Strategy.
func (s *Strategy) Authenticate(c *passport.Context, r *http.Request) {
	token := s.extractToken(r)
	if token == "" {
		c.Fail("Bearer", http.StatusUnauthorized)
		return
	}

	claims, err := Verify(token, s.resolver())
	if err != nil {
		c.Fail("Bearer error=\"invalid_token\"", http.StatusUnauthorized)
		return
	}
	if s.opts.Issuer != "" && claims.Issuer() != s.opts.Issuer {
		c.Fail("Bearer error=\"invalid_issuer\"", http.StatusUnauthorized)
		return
	}
	if s.opts.Audience != "" && !contains(claims.Audience(), s.opts.Audience) {
		c.Fail("Bearer error=\"invalid_audience\"", http.StatusUnauthorized)
		return
	}

	if s.verify == nil {
		c.Success(map[string]any(claims))
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

// VerifyToken verifies a raw compact JWT using the strategy's configured key
// source (JWKS endpoint, static Set, or custom resolver) and returns its
// claims. It validates the signature and the exp/nbf time claims but not the
// issuer/audience — callers that need those should check the returned claims.
// It is exported so other strategies (OpenID Connect) can reuse the cached
// key resolution.
func (s *Strategy) VerifyToken(token string) (Claims, error) {
	return Verify(token, s.resolver())
}

// resolver builds the KeyResolver honoring the algorithm allow-list and the
// configured key source (custom resolver, static set, or JWKS endpoint).
func (s *Strategy) resolver() KeyResolver {
	return func(kid, alg string) (any, error) {
		if strings.HasPrefix(alg, "HS") {
			// Never verify HS* against JWKS material (key-confusion guard).
			return nil, ErrAlgorithm
		}
		if len(s.opts.Algorithms) > 0 && !contains(s.opts.Algorithms, alg) {
			return nil, ErrAlgorithm
		}
		if s.opts.Resolve != nil {
			return s.opts.Resolve(kid, alg)
		}
		if s.opts.Set != nil {
			return s.opts.Set.Key(kid)
		}
		return s.keyFromEndpoint(kid)
	}
}

// keyFromEndpoint returns a key for kid from the cached JWKS, refetching once if
// the kid is unknown or the cache has expired.
func (s *Strategy) keyFromEndpoint(kid string) (any, error) {
	if s.opts.JWKSURL == "" {
		return nil, ErrKey
	}
	s.mu.Lock()
	set := s.cached
	stale := set == nil || time.Since(s.fetchedAt) > s.opts.CacheTTL
	s.mu.Unlock()

	if !stale {
		if key, err := set.Key(kid); err == nil {
			return key, nil
		}
		// Unknown kid — keys may have rotated; fall through to a refetch.
	}

	fresh, err := s.fetch()
	if err != nil {
		if set != nil {
			// Serve stale keys rather than failing outright on a transient error.
			return set.Key(kid)
		}
		return nil, err
	}
	s.mu.Lock()
	s.cached = fresh
	s.fetchedAt = time.Now()
	s.mu.Unlock()
	return fresh.Key(kid)
}

// fetch downloads and parses the JWKS document.
func (s *Strategy) fetch() (*Set, error) {
	req, err := http.NewRequest(http.MethodGet, s.opts.JWKSURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := s.opts.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, errors.New("jwks: fetch returned status " + resp.Status)
	}
	var set Set
	if err := json.NewDecoder(resp.Body).Decode(&set); err != nil {
		return nil, err
	}
	return &set, nil
}

func (s *Strategy) extractToken(r *http.Request) string {
	if !s.opts.TokenFromParam {
		h := r.Header.Get("Authorization")
		if len(h) > 7 && strings.EqualFold(h[:7], "bearer ") {
			return strings.TrimSpace(h[7:])
		}
		return ""
	}
	if t := r.URL.Query().Get("id_token"); t != "" {
		return t
	}
	if t := r.URL.Query().Get("access_token"); t != "" {
		return t
	}
	_ = r.ParseForm()
	if t := r.PostFormValue("id_token"); t != "" {
		return t
	}
	return r.PostFormValue("access_token")
}

func contains(ss []string, want string) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
	}
	return false
}
