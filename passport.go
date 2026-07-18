// The package overview lives in doc.go.
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

	// Multi-layer chains mirroring Passport.js's Authenticator. They are empty
	// by default; the single serialize/deserialize functions above remain the
	// common path. See serde.go.
	serializers      []Serializer
	deserializers    []Deserializer
	infoTransformers []InfoTransformer
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
// chaining. Like Passport.js, which throws "Authentication strategies must have
// a name", Use panics when the strategy reports an empty Name(); register such a
// strategy with UseNamed instead.
func (p *Passport) Use(s Strategy) *Passport {
	name := s.Name()
	if name == "" {
		panic("passport: Authentication strategies must have a name")
	}
	return p.UseNamed(name, s)
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
