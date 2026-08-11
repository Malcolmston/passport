package passport

import (
	"net/http"
)

// Middleware is the standard net/http middleware shape: it wraps a handler and
// returns a new handler. All passport middleware (Initialize, Session,
// Authenticate) uses this shape so it composes with any net/http router.
type Middleware func(next http.Handler) http.Handler

// Chain applies middleware to a handler, with the first middleware in the list
// running outermost (first) — the same order you would register them in.
//
//	handler := passport.Chain(mux, p.Initialize(), p.Session())
func Chain(h http.Handler, mw ...Middleware) http.Handler {
	for i := len(mw) - 1; i >= 0; i-- {
		h = mw[i](h)
	}
	return h
}

// Options controls how Authenticate handles the outcome of a strategy.
type Options struct {
	// Session controls whether a persistent login session is established on a
	// successful authentication. It is a *bool with three states, matching
	// Passport.js's `session` option:
	//
	//   - nil   → the default: a session IS established (Passport.js session:true).
	//   - false → stateless authentication (e.g. API tokens): no session.
	//   - true  → explicitly establish a session.
	//
	// It is a pointer, not a bool, so the zero value of an Options literal that
	// only sets other fields — e.g. Options{SuccessRedirect: "/"} — still
	// defaults to establishing a session, exactly as the idiomatic Passport.js
	// call authenticate('local', {successRedirect: '/'}) does. Use NoSession()
	// for stateless auth and WithSession() to be explicit.
	Session *bool

	// SuccessRedirect, if set, redirects here after a successful login instead
	// of calling the next handler.
	SuccessRedirect string

	// FailureRedirect, if set, redirects here on authentication failure instead
	// of responding with the failure status.
	FailureRedirect string

	// FailureStatus overrides the HTTP status sent on failure (default 401).
	FailureStatus int

	// FailureMessage, if true, does not swallow the strategy's challenge; the
	// challenge text is written as the failure response body.
	FailureMessage bool
}

func defaultOptions() *Options {
	// Session left nil: a session is established by default (Passport.js session:true).
	return &Options{}
}

// useSession reports whether a session should be established for this attempt.
// A nil Session means the default (on); an explicit *false disables it.
func (o *Options) useSession() bool {
	return o.Session == nil || *o.Session
}

// NoSession returns a *bool for Options.Session that disables session creation
// for an authentication attempt, for stateless auth such as API tokens. It is
// shorthand for taking the address of a false bool.
func NoSession() *bool { b := false; return &b }

// WithSession returns a *bool for Options.Session that forces session creation.
// Since Session defaults to on when left nil, this is only needed to be
// explicit about the default.
func WithSession() *bool { b := true; return &b }

// Authenticate returns middleware that authenticates a request using the named
// strategy. On success it attaches the user to the request (and, unless
// disabled, logs the user in) before invoking the next handler. On failure it
// responds according to opts.
//
// Use it to guard routes or as the handler chain for a login endpoint:
//
//	login := passport.Chain(
//		http.HandlerFunc(onLoginSuccess),
//		p.Authenticate("local", passport.Options{SuccessRedirect: "/"}),
//	)
func (p *Passport) Authenticate(name string, opts ...Options) Middleware {
	o := defaultOptions()
	if len(opts) > 0 {
		merged := opts[0]
		o = &merged
		// Session defaults to true; callers opt out explicitly.
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			strat, ok := p.strategies[name]
			if !ok {
				http.Error(w, "passport: unknown strategy \""+name+"\"", http.StatusInternalServerError)
				return
			}

			c := &Context{Options: o, Writer: w}
			strat.Authenticate(c, r)

			switch c.result {
			case outcomeSuccess:
				st := stateFrom(r)
				if st != nil {
					st.user = c.user
					st.authed = true
				}
				if o.useSession() {
					if err := p.LogIn(w, r, c.user); err != nil {
						http.Error(w, err.Error(), http.StatusInternalServerError)
						return
					}
				}
				if o.SuccessRedirect != "" {
					http.Redirect(w, r, o.SuccessRedirect, http.StatusFound)
					return
				}
				next.ServeHTTP(w, r)

			case outcomeFail:
				if o.FailureRedirect != "" {
					http.Redirect(w, r, o.FailureRedirect, http.StatusFound)
					return
				}
				status := c.status
				if o.FailureStatus != 0 {
					status = o.FailureStatus
				}
				if status == 0 {
					status = http.StatusUnauthorized
				}
				msg := http.StatusText(status)
				if o.FailureMessage && c.challenge != "" {
					msg = c.challenge
				}
				// Emit WWW-Authenticate only for a genuine HTTP-auth challenge
				// (FailWithChallenge) and only on a 401, matching Passport.js.
				if c.www && c.challenge != "" && status == http.StatusUnauthorized {
					w.Header().Set("WWW-Authenticate", c.challenge)
				}
				http.Error(w, msg, status)

			case outcomeRedirect:
				http.Redirect(w, r, c.location, c.status)

			case outcomeError:
				http.Error(w, c.err.Error(), http.StatusInternalServerError)

			case outcomePass, outcomeNone:
				// Strategy declined: continue the chain unauthenticated.
				next.ServeHTTP(w, r)
			}
		})
	}
}

// RequireLogin returns middleware that allows the request through only when it
// is authenticated; otherwise it redirects to redirectTo (or responds 401 when
// redirectTo is empty).
func (p *Passport) RequireLogin(redirectTo string) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if IsAuthenticated(r) {
				next.ServeHTTP(w, r)
				return
			}
			if redirectTo != "" {
				http.Redirect(w, r, redirectTo, http.StatusFound)
				return
			}
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		})
	}
}
