// Package passport is a Go port of the Node.js Passport authentication
// middleware. It provides pluggable, strategy-based authentication for net/http
// servers (and any framework built on net/http, such as express-go). Rather than
// bake in one authentication mechanism, passport defines a small Strategy
// contract and lets you compose it with interchangeable strategies —
// username/password, HTTP Basic/Digest, bearer and API tokens, TOTP/HOTP,
// magic links, JWT/JWKS, OAuth 1.0a and OAuth 2.0 providers, OpenID Connect,
// SAML, and WebAuthn passkeys — under a single, uniform API. It depends only on
// the Go standard library.
//
// # Concepts
//
// The three moving parts mirror Passport.js. Strategies verify credentials: a
// Strategy inspects the incoming request in its Authenticate method and reports
// exactly one outcome on the supplied *Context (Success, Fail, Redirect, Error,
// or Pass). Serialize/Deserialize functions bridge a user object and the session:
// SerializeUser reduces an authenticated user to a stable id stored in the
// session, and DeserializeUser reconstructs the user from that id on later
// requests. Middleware wires it all into a net/http handler chain: Initialize
// bootstraps per-request state and loads the session, Session restores the
// logged-in user, and Authenticate runs a named strategy to guard a route or
// power a login endpoint.
//
// # Request flow
//
// A request flows through the middleware in order. Chain applies middleware
// outermost-first, so Initialize runs before Session, which runs before your
// routes. Initialize installs a shared authentication state on the request
// context and hydrates the session from its cookie; Session then deserializes any
// stored user id so handlers can call User and IsAuthenticated. When a request
// hits an Authenticate("name") route, passport looks up the registered strategy,
// runs it, and dispatches on the recorded outcome: on Success it attaches the
// user and (unless Options.Session is false) calls LogIn to persist the session
// and set the cookie; on Fail it writes the challenge/status (or redirects to
// FailureRedirect); on Redirect it sends the user agent to an external provider;
// on Error it returns 500; and on Pass/none it continues the chain
// unauthenticated. LogIn regenerates the session id to defeat session fixation,
// and LogOut clears it. RequireLogin guards a route for already-authenticated
// users, AuthenticateCallback hands the outcome to your own callback, and
// AuthenticateAny tries several strategies in turn.
//
// # Strategies
//
// Concrete strategies live in subpackages under strategies/ — 104 of them, each
// an independent, standard-library-only package implementing Strategy. They plug
// in through Use (or UseNamed to register the same strategy type more than once).
// Each subpackage's New returns a value satisfying the Strategy interface, so
// wiring a new provider is a one-line change. The 67 OAuth 2.0 provider presets
// (github, google, slack, discord, apple, and many more) share the
// strategies/oauth2 base and additionally implement OAuth2Provider, so generic
// code can build the authorization URL without importing a specific provider.
// OpenID Connect id_tokens are verified against rotating RS256/ES256 keys via the
// jwks and openidconnect strategies (Auth0, Okta, Azure AD, Cognito, …).
//
// # Sessions
//
// Sessions are backed by a pluggable Store — an in-memory MemoryStore by default,
// replaceable via SetStore with a Redis- or database-backed implementation — and
// cookie behavior is tunable with SecureCookies. Stateless flows (API tokens, JWT
// bearer) can skip sessions entirely with Options{Session: false}.
//
// # Getting started
//
// Typical wiring registers one or more strategies, sets the
// serialize/deserialize functions, and installs the middleware:
//
//	p := passport.New()
//	p.Use(local.New(func(username, password string) (any, error) { ... }))
//	p.SerializeUser(func(user any) (string, error) { ... })
//	p.DeserializeUser(func(id string, r *http.Request) (any, error) { ... })
//
//	mux := http.NewServeMux()
//	mux.Handle("/login", p.Authenticate("local", passport.Options{SuccessRedirect: "/"})(nil))
//	handler := passport.Chain(mux, p.Initialize(), p.Session())
//
// The API deliberately tracks Passport.js names and behavior (Use, Authenticate,
// serializeUser/deserializeUser, req.login/req.logout, req.user,
// req.isAuthenticated) so that porting an Express application is largely
// mechanical, while adapting idioms — middleware as functions, outcomes on a
// Context — to Go's net/http.
package passport
