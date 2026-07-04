package passport

import "net/http"

// This file collects the small, optional capability interfaces that build on
// top of the canonical Strategy interface (declared in strategy.go). Strategy
// remains the single contract every strategy must satisfy; the interfaces here
// describe *additional* capabilities that a strategy MAY expose so that generic
// code can detect and use them without depending on a concrete package.

// Named is the naming half of Strategy, factored out as its own interface.
//
// Every Strategy is a Named (Strategy embeds Name), so a value can be
// type-asserted to Named in contexts where only the registration name is
// needed and the full Strategy contract is unavailable or unnecessary.
type Named interface {
	// Name is the default name a strategy registers under, e.g. "local".
	Name() string
}

// Authenticator is the request-handling half of Strategy. It is the minimal
// behavioral contract: given a request, record an outcome on the Context.
type Authenticator interface {
	// Authenticate runs the strategy against the request, recording its result
	// on c before returning.
	Authenticate(c *Context, r *http.Request)
}

// OAuth2Provider is the optional capability interface implemented by
// authorization-code strategies (the concrete provider packages under
// strategies/, e.g. github, google, gitlab, discord, facebook, all of which
// wrap strategies/oauth2). Beyond the Strategy contract it can build the
// provider's authorization-endpoint URL for a given opaque state value, which
// lets callers initiate the redirect leg without reaching into a specific
// provider package.
//
// It intentionally references only the root package and the standard library
// so that the root package stays free of a dependency on strategies/oauth2
// (which itself imports the root package).
type OAuth2Provider interface {
	Strategy

	// AuthCodeURL builds the provider's authorization URL for the given state.
	AuthCodeURL(state string) string
}

// Compile-time confirmation that the two halves compose back into Strategy.
var (
	_ Named         = Strategy(nil)
	_ Authenticator = Strategy(nil)
)
