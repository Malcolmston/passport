// This file wires the jwks verifier into a passport.Strategy so OpenID Connect
// providers (Google, Auth0, Okta, Azure AD, Cognito, ...) that sign id_tokens
// with rotating RS256/ES256 keys can be authenticated directly against their
// published JWKS endpoint.
package jwks

import (
	"context"
	"encoding/json"
	"errors"
	"io"
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
	// MaxRefreshesPerMinute caps how many times the JWKS document may be
	// fetched in any one-minute window (default
	// DefaultMaxRefreshesPerMinute).
	//
	// Seeing an unknown "kid" triggers a refetch, because that is how key
	// rotation is picked up promptly. But the kid comes from an
	// unauthenticated token header, so without a cap anyone can turn each
	// request they send into an outbound fetch — using this server to hammer
	// the provider's JWKS endpoint, and stalling its own request handlers
	// behind those fetches. Once the budget for the current window is spent,
	// an unknown kid is reported as ErrKey against the cached set until the
	// window rolls over. This mirrors the jwksRequestsPerMinute rate limit in
	// Node's jwks-rsa.
	//
	// Set it to a negative value to allow unthrottled refetching.
	MaxRefreshesPerMinute int
	// HTTPClient fetches the JWKS document (default http.DefaultClient).
	HTTPClient *http.Client
	// MaxJWKSBytes caps the size of the JWKS document that will be read
	// (default DefaultMaxJWKSBytes), so a hostile or misbehaving endpoint
	// cannot exhaust memory with an endless response body.
	MaxJWKSBytes int64
	// FetchTimeout bounds a single JWKS fetch (default DefaultFetchTimeout).
	// It applies only when HTTPClient has no timeout of its own.
	FetchTimeout time.Duration
	// TokenFromParam, when true, reads the token from the "id_token" or
	// "access_token" query/form field instead of the Authorization: Bearer
	// header (the default).
	TokenFromParam bool
}

// Defaults applied by New for the corresponding zero-valued Options fields.
const (
	// DefaultCacheTTL is how long fetched keys are reused before a refresh.
	DefaultCacheTTL = time.Hour
	// DefaultMaxRefreshesPerMinute throttles unknown-kid refetches. Ten per
	// minute is the same budget Node's jwks-rsa uses by default: ample for
	// real key rotation, which happens on the order of days, while capping the
	// outbound traffic an unauthenticated caller can induce.
	DefaultMaxRefreshesPerMinute = 10
	// DefaultMaxJWKSBytes caps the JWKS response body. Real key sets are a few
	// kilobytes; 1 MiB leaves ample headroom.
	DefaultMaxJWKSBytes int64 = 1 << 20
	// DefaultFetchTimeout bounds a single JWKS fetch.
	DefaultFetchTimeout = 10 * time.Second
)

// Strategy authenticates a request carrying a JWT verified against a JWKS.
type Strategy struct {
	opts   Options
	verify VerifyFunc

	mu          sync.Mutex
	cached      *Set
	fetchedAt   time.Time
	windowStart time.Time
	windowCount int
}

// New creates a JWKS-backed strategy. verify may be nil, in which case the raw
// Claims become the authenticated user.
func New(opts Options, verify VerifyFunc) *Strategy {
	if opts.CacheTTL == 0 {
		opts.CacheTTL = DefaultCacheTTL
	}
	if opts.MaxRefreshesPerMinute == 0 {
		opts.MaxRefreshesPerMinute = DefaultMaxRefreshesPerMinute
	}
	if opts.MaxJWKSBytes == 0 {
		opts.MaxJWKSBytes = DefaultMaxJWKSBytes
	}
	if opts.FetchTimeout == 0 {
		opts.FetchTimeout = DefaultFetchTimeout
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

// refreshAllowedLocked reports whether another JWKS fetch fits in the current
// one-minute budget, consuming a slot when it does. The caller must hold s.mu.
func (s *Strategy) refreshAllowedLocked(now time.Time) bool {
	if s.opts.MaxRefreshesPerMinute <= 0 {
		return true
	}
	if s.windowStart.IsZero() || now.Sub(s.windowStart) >= time.Minute {
		s.windowStart = now
		s.windowCount = 0
	}
	if s.windowCount >= s.opts.MaxRefreshesPerMinute {
		return false
	}
	s.windowCount++
	return true
}

// keyFromEndpoint returns a key for kid from the cached JWKS, refetching if the
// kid is unknown or the cache has expired — but no more often than
// Options.MaxRefreshesPerMinute, so an unauthenticated caller cannot drive
// unbounded outbound fetches by sending tokens with made-up kids.
func (s *Strategy) keyFromEndpoint(kid string) (any, error) {
	if s.opts.JWKSURL == "" {
		return nil, ErrKey
	}
	now := time.Now()

	s.mu.Lock()
	set := s.cached
	stale := set == nil || now.Sub(s.fetchedAt) > s.opts.CacheTTL
	if !stale {
		if key, err := set.Key(kid); err == nil {
			s.mu.Unlock()
			return key, nil
		}
		// Unknown kid — keys may have rotated; fall through to a refetch.
	}
	allowed := s.refreshAllowedLocked(now)
	s.mu.Unlock()

	if !allowed {
		// Out of refresh budget. Answer from whatever is cached rather than
		// issuing another fetch; with no cache at all there is nothing to do
		// but reject.
		if set != nil {
			return set.Key(kid)
		}
		return nil, ErrKey
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

// fetch downloads and parses the JWKS document. The request is bounded by
// Options.FetchTimeout and the response body by Options.MaxJWKSBytes, so a slow
// or endlessly streaming endpoint cannot pin a request handler or exhaust
// memory.
func (s *Strategy) fetch() (*Set, error) {
	ctx := context.Background()
	if s.opts.FetchTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, s.opts.FetchTimeout)
		defer cancel()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.opts.JWKSURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := s.opts.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, errors.New("jwks: fetch returned status " + resp.Status)
	}
	var body io.Reader = resp.Body
	if s.opts.MaxJWKSBytes > 0 {
		body = io.LimitReader(resp.Body, s.opts.MaxJWKSBytes)
	}
	var set Set
	if err := json.NewDecoder(body).Decode(&set); err != nil {
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
