package passport

import "net/http"

// AuthenticateCallback runs the named strategy and invokes cb with the outcome
// instead of writing a default response. On success the user is attached to the
// request (so cb may call p.LogIn). err is non-nil only for internal strategy
// errors; a failed auth yields (nil user) with info carrying the challenge/info.
//
// It mirrors Passport.js's custom-callback form:
//
//	passport.authenticate('local', function(err, user, info){ ... })
//
// Redirects requested by the strategy (e.g. an OAuth handshake) are performed
// directly and cb is not called for them.
func (p *Passport) AuthenticateCallback(name string, cb func(w http.ResponseWriter, r *http.Request, err error, user any, info any)) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		strat, ok := p.strategies[name]
		if !ok {
			cb(w, r, &unknownStrategyError{name: name}, nil, nil)
			return
		}

		c := &Context{Options: defaultOptions(), Writer: w}
		strat.Authenticate(c, r)

		switch c.result {
		case outcomeSuccess:
			st := stateFrom(r)
			if st != nil {
				st.user = c.user
				st.authed = true
			}
			cb(w, r, nil, c.user, c.info)

		case outcomeFail:
			status := c.status
			if status == 0 {
				status = http.StatusUnauthorized
			}
			info := map[string]any{"message": c.challenge, "status": status}
			cb(w, r, nil, nil, info)

		case outcomeRedirect:
			http.Redirect(w, r, c.location, c.status)

		case outcomeError:
			cb(w, r, c.err, nil, nil)

		case outcomePass, outcomeNone:
			cb(w, r, nil, nil, nil)
		}
	})
}

// unknownStrategyError is returned to an AuthenticateCallback when the named
// strategy has not been registered.
type unknownStrategyError struct{ name string }

func (e *unknownStrategyError) Error() string {
	return "passport: unknown strategy \"" + e.name + "\""
}

// AuthenticateAny tries each named strategy in order and succeeds on the first
// that authenticates; if none do, it responds like Authenticate's failure path
// using the LAST strategy's failure (or 401).
func (p *Passport) AuthenticateAny(names []string, opts ...Options) Middleware {
	o := defaultOptions()
	if len(opts) > 0 {
		merged := opts[0]
		o = &merged
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var last *Context // most recent failing context, for the challenge

			for _, name := range names {
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
					if o.Session {
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
					return

				case outcomeError:
					http.Error(w, c.err.Error(), http.StatusInternalServerError)
					return

				case outcomeRedirect:
					http.Redirect(w, r, c.location, c.status)
					return

				case outcomeFail:
					last = c
					// try the next strategy

				case outcomePass, outcomeNone:
					// declined; try the next strategy
				}
			}

			// No strategy succeeded: respond with the last failure (or 401).
			if o.FailureRedirect != "" {
				http.Redirect(w, r, o.FailureRedirect, http.StatusFound)
				return
			}
			status := http.StatusUnauthorized
			challenge := ""
			if last != nil {
				if last.status != 0 {
					status = last.status
				}
				challenge = last.challenge
			}
			if o.FailureStatus != 0 {
				status = o.FailureStatus
			}
			msg := http.StatusText(status)
			if o.FailureMessage && challenge != "" {
				msg = challenge
			}
			if challenge != "" {
				w.Header().Set("WWW-Authenticate", challenge)
			}
			http.Error(w, msg, status)
		})
	}
}
