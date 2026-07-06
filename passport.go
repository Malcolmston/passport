// Package passport is a Go port of the Node.js Passport authentication
// middleware. It provides pluggable, strategy-based authentication for net/http
// servers (and any framework built on net/http, such as express-go). Rather than
// bake in one authentication mechanism, passport defines a small Strategy
// contract and lets you compose it with dozens of interchangeable strategies —
// username/password, OAuth 1.0a/OAuth 2.0 providers, OpenID Connect, TOTP,
// WebAuthn passkeys, signed tokens, and more — under a single, uniform API.
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
// and LogOut clears it.
//
// Concrete strategies live in subpackages under strategies/ and plug in through
// Use (or UseNamed to register the same strategy type more than once). Each
// subpackage's New returns a value satisfying the Strategy interface, so wiring a
// new provider is a one-line change; the OAuth 2.0 provider presets (slack,
// spotify, twitch, and many others) additionally implement OAuth2Provider so
// generic code can build the authorization URL without importing a specific
// provider. Sessions are backed by a pluggable Store (an in-memory MemoryStore by
// default, replaceable via SetStore with a Redis- or database-backed
// implementation), and cookie behavior is tunable with SecureCookies. Stateless
// flows (API tokens) can skip sessions entirely with Options{Session: false}.
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

import (
	"context"
	"errors"
	"net/http"
)

// SerializeFunc converts a user object into a stable session id (typically the
// user's primary key).
type SerializeFunc func(user any) (id string, err error)

// DeserializeFunc reconstructs a user object from a previously serialized id.
// The request is provided for stores that need request-scoped context.
type DeserializeFunc func(id string, r *http.Request) (user any, err error)

// Passport is a registry of strategies plus the serialize/deserialize logic and
// session configuration used to authenticate requests.
type Passport struct {
	strategies  map[string]Strategy
	serialize   SerializeFunc
	deserialize DeserializeFunc
	sessions    *sessionManager
	userKey     string // session key under which the serialized user id is stored
}

// New creates a Passport backed by an in-memory session store. Configure it
// with Use, SerializeUser, and DeserializeUser before installing its middleware.
func New() *Passport {
	return &Passport{
		strategies: make(map[string]Strategy),
		sessions:   newSessionManager(NewMemoryStore()),
		userKey:    "passport.user",
	}
}

// Use registers a strategy under its default Name(). It returns the Passport for
// chaining.
func (p *Passport) Use(s Strategy) *Passport {
	return p.UseNamed(s.Name(), s)
}

// UseNamed registers a strategy under an explicit name, allowing the same
// strategy type to be registered multiple times with different configuration.
func (p *Passport) UseNamed(name string, s Strategy) *Passport {
	p.strategies[name] = s
	return p
}

// Unuse removes a previously registered strategy.
func (p *Passport) Unuse(name string) *Passport {
	delete(p.strategies, name)
	return p
}

// SerializeUser sets the function used to reduce a user to a session id.
func (p *Passport) SerializeUser(fn SerializeFunc) *Passport {
	p.serialize = fn
	return p
}

// DeserializeUser sets the function used to reconstruct a user from a session id.
func (p *Passport) DeserializeUser(fn DeserializeFunc) *Passport {
	p.deserialize = fn
	return p
}

// SetStore replaces the session store (e.g. with a Redis-backed Store).
func (p *Passport) SetStore(store Store) *Passport {
	name := p.sessions.cookieName
	p.sessions = newSessionManager(store)
	p.sessions.cookieName = name
	return p
}

// SecureCookies marks the session cookie Secure (send only over HTTPS).
func (p *Passport) SecureCookies(secure bool) *Passport {
	p.sessions.secure = secure
	return p
}

// state holds the per-request authentication state. A pointer to it is stored
// in the request context so that middleware and handlers can read and mutate a
// single shared value across the chain without rebuilding the request.
type state struct {
	passport *Passport
	session  *session
	writer   http.ResponseWriter
	user     any
	authed   bool
}

type ctxKey struct{}

var stateKey = ctxKey{}

func stateFrom(r *http.Request) *state {
	s, _ := r.Context().Value(stateKey).(*state)
	return s
}

// Initialize returns middleware that bootstraps passport for each request: it
// loads the session and installs the shared authentication state. It must be
// registered before Session and Authenticate.
func (p *Passport) Initialize() Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			st := &state{
				passport: p,
				session:  p.sessions.load(r),
				writer:   w,
			}
			ctx := context.WithValue(r.Context(), stateKey, st)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// Session returns middleware that restores a logged-in user from the session on
// each request by deserializing the stored user id. It must run after
// Initialize.
func (p *Passport) Session() Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			st := stateFrom(r)
			if st != nil && p.deserialize != nil {
				if raw, ok := st.session.Get(p.userKey); ok {
					if id, ok := raw.(string); ok && id != "" {
						if user, err := p.deserialize(id, r); err == nil && user != nil {
							st.user = user
							st.authed = true
						}
					}
				}
			}
			next.ServeHTTP(w, r)
		})
	}
}

// LogIn establishes a login session for user, serializing it into the session
// store and setting the session cookie on w. It is the Go equivalent of
// Passport.js's req.login.
func (p *Passport) LogIn(w http.ResponseWriter, r *http.Request, user any) error {
	st := stateFrom(r)
	if st == nil {
		return errors.New("passport: LogIn called without Initialize() middleware")
	}
	st.user = user
	st.authed = true

	if p.serialize == nil {
		// Stateless login: mark the request authenticated without a session.
		return nil
	}
	id, err := p.serialize(user)
	if err != nil {
		return err
	}
	// Regenerate the session id on login to prevent session fixation.
	if err := st.session.regenerate(); err != nil {
		return err
	}
	st.session.Set(p.userKey, id)
	return st.session.save(w)
}

// LogOut clears the current login session and removes the session cookie.
func (p *Passport) LogOut(w http.ResponseWriter, r *http.Request) error {
	st := stateFrom(r)
	if st == nil {
		return errors.New("passport: LogOut called without Initialize() middleware")
	}
	st.user = nil
	st.authed = false
	st.session.Delete(p.userKey)
	st.session.destroy(w)
	return nil
}

// User returns the authenticated user for the request, or nil if the request is
// not authenticated.
func User(r *http.Request) any {
	if st := stateFrom(r); st != nil {
		return st.user
	}
	return nil
}

// IsAuthenticated reports whether the request has an authenticated user.
func IsAuthenticated(r *http.Request) bool {
	st := stateFrom(r)
	return st != nil && st.authed && st.user != nil
}
