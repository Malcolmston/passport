package strategies_test

// This file exercises a cross-cutting contract that every strategy in the
// repository is expected to honor, independent of its concrete package. It
// enumerates a representative set of strategies, constructs each with minimal
// arguments, and asserts:
//
//   - the concrete type implements passport.Strategy (compile-time),
//   - Name() returns a non-empty, lowercase, stable token, unique across the
//     set, and
//   - Authenticate on a blank request records SOME outcome on the Context
//     (never ResultNone) — a strategy must never silently do nothing.
//
// The OAuth2 providers additionally share a sub-test (TestOAuth2ProviderBase)
// proving they all resolve to a working *oauth2.Strategy with non-empty
// authorization and token endpoints and a redirect on the first leg.

import (
	"net/http"
	"net/http/httptest"
	"regexp"
	"testing"

	"github.com/malcolmston/passport"
	"github.com/malcolmston/passport/strategies/anonymous"
	"github.com/malcolmston/passport/strategies/apikey"
	"github.com/malcolmston/passport/strategies/basic"
	"github.com/malcolmston/passport/strategies/basicverify"
	"github.com/malcolmston/passport/strategies/bearer"
	"github.com/malcolmston/passport/strategies/bearertoken"
	"github.com/malcolmston/passport/strategies/discord"
	"github.com/malcolmston/passport/strategies/facebook"
	"github.com/malcolmston/passport/strategies/github"
	"github.com/malcolmston/passport/strategies/gitlab"
	"github.com/malcolmston/passport/strategies/google"
	"github.com/malcolmston/passport/strategies/local"
	"github.com/malcolmston/passport/strategies/oauth2"
)

// nameRe accepts the lowercase, hyphen/dot/underscore token shape the bundled
// strategies use (e.g. "local", "basic-verify", "bearer-token").
var nameRe = regexp.MustCompile(`^[a-z0-9]+([._-][a-z0-9]+)*$`)

// strategyCase pairs a strategy with the outcome a blank request must produce.
type strategyCase struct {
	strategy passport.Strategy
	// wantResult is the outcome expected for a blank GET "/" request. It is
	// always non-None; which specific outcome depends on the strategy family.
	wantResult passport.Result
}

// cases enumerates the representative strategy set under test. Constructing
// each value here is itself the compile-time assertion that the concrete type
// implements passport.Strategy, since the field is typed as passport.Strategy.
func cases() []strategyCase {
	return []strategyCase{
		{local.New(func(_, _ string) (any, error) { return nil, nil }), passport.ResultFail},
		{basic.New(func(_, _ string) (any, error) { return nil, nil }), passport.ResultFail},
		{basicverify.New(basicverify.Options{Verify: func(_, _ string) (any, error) { return nil, nil }}), passport.ResultFail},
		{bearer.New(func(_ string) (any, error) { return nil, nil }), passport.ResultFail},
		{bearertoken.New(func(_ string) (any, error) { return nil, nil }), passport.ResultFail},
		{apikey.New(apikey.Options{Verify: func(_ string) (any, error) { return nil, nil }}), passport.ResultFail},
		{anonymous.New(), passport.ResultPass},
		{github.New("id", "secret", "https://app.example/cb", nil), passport.ResultRedirect},
		{google.New("id", "secret", "https://app.example/cb", nil), passport.ResultRedirect},
		{facebook.New("id", "secret", "https://app.example/cb", nil), passport.ResultRedirect},
		{gitlab.New("id", "secret", "https://app.example/cb", nil), passport.ResultRedirect},
		{discord.New("id", "secret", "https://app.example/cb", nil), passport.ResultRedirect},
	}
}

func TestStrategyCompliance(t *testing.T) {
	seen := map[string]bool{}
	for _, tc := range cases() {
		name := tc.strategy.Name()
		t.Run(name, func(t *testing.T) {
			// Name is non-empty, well-shaped, and lowercase.
			if name == "" {
				t.Fatal("Name() returned empty string")
			}
			if !nameRe.MatchString(name) {
				t.Errorf("Name() = %q is not a lowercase token matching %s", name, nameRe)
			}
			// Name is stable across calls.
			if again := tc.strategy.Name(); again != name {
				t.Errorf("Name() is not stable: first %q, then %q", name, again)
			}
			// Name is unique across the set.
			if seen[name] {
				t.Errorf("duplicate strategy name %q", name)
			}
			seen[name] = true

			// Authenticate on a blank request records some outcome.
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			c := &passport.Context{}
			tc.strategy.Authenticate(c, r)
			if c.Result() == passport.ResultNone {
				t.Fatalf("Authenticate left ResultNone on a blank request (err=%v, challenge=%q)",
					c.Err(), c.Challenge())
			}
			if c.Result() != tc.wantResult {
				t.Errorf("Authenticate result = %v, want %v", c.Result(), tc.wantResult)
			}
		})
	}

	if len(seen) != len(cases()) {
		t.Errorf("expected %d unique names, saw %d", len(cases()), len(seen))
	}
}

// oauth2Provider constructs a provider's *oauth2.Strategy under a stable label.
type oauth2Provider struct {
	label    string
	strategy *oauth2.Strategy
}

// oauth2Providers is the set of OAuth2 provider packages that wrap the shared
// oauth2 base. They exist purely to preset endpoints and scopes.
func oauth2Providers() []oauth2Provider {
	return []oauth2Provider{
		{"github", github.New("id", "secret", "https://app.example/cb", nil)},
		{"google", google.New("id", "secret", "https://app.example/cb", nil)},
		{"facebook", facebook.New("id", "secret", "https://app.example/cb", nil)},
		{"gitlab", gitlab.New("id", "secret", "https://app.example/cb", nil)},
		{"discord", discord.New("id", "secret", "https://app.example/cb", nil)},
	}
}

// TestOAuth2ProviderBase asserts the shared abstraction: every provider yields
// a working *oauth2.Strategy with non-empty authorization and token endpoints,
// satisfies the passport.OAuth2Provider capability interface, and redirects on
// the first leg of the flow.
func TestOAuth2ProviderBase(t *testing.T) {
	for _, p := range oauth2Providers() {
		t.Run(p.label, func(t *testing.T) {
			// The provider capability interface is satisfied.
			var _ passport.OAuth2Provider = p.strategy

			if p.strategy.Name() != p.label {
				t.Errorf("Name() = %q, want %q", p.strategy.Name(), p.label)
			}
			if p.strategy.AuthURL() == "" {
				t.Error("AuthURL() is empty")
			}
			if p.strategy.TokenURL() == "" {
				t.Error("TokenURL() is empty")
			}

			// AuthCodeURL embeds the authorization endpoint and echoes state.
			got := p.strategy.AuthCodeURL("state-xyz")
			if got == "" {
				t.Fatal("AuthCodeURL returned empty string")
			}

			// First leg with no ?code= redirects to the provider.
			r := httptest.NewRequest(http.MethodGet, "/login?state=state-xyz", nil)
			c := &passport.Context{}
			p.strategy.Authenticate(c, r)
			if c.Result() != passport.ResultRedirect {
				t.Fatalf("first-leg Authenticate result = %v, want ResultRedirect", c.Result())
			}
		})
	}
}
