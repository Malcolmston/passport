package passport

import "net/http"

// Strategy is the interface every authentication strategy implements. A
// strategy inspects the incoming request inside Authenticate and reports its
// result by calling exactly one of the outcome methods on the supplied
// *Context (Success, Fail, Redirect, Error, or Pass), mirroring the strategy
// contract of Passport.js.
type Strategy interface {
	// Name is the default name a strategy registers under, e.g. "local".
	Name() string

	// Authenticate runs the strategy against the request. It must record its
	// result on c before returning.
	Authenticate(c *Context, r *http.Request)
}

// Result enumerates the possible outcomes a strategy can report on a Context.
type Result int

const (
	// ResultNone means the strategy did not report any outcome.
	ResultNone Result = iota
	// ResultSuccess means authentication succeeded.
	ResultSuccess
	// ResultFail means authentication failed (bad or missing credentials).
	ResultFail
	// ResultRedirect means the strategy wants to redirect the user agent.
	ResultRedirect
	// ResultError means an internal error occurred.
	ResultError
	// ResultPass means the strategy declined to handle the request.
	ResultPass
)

// aliases kept for internal readability.
type outcome = Result

const (
	outcomeNone     = ResultNone
	outcomeSuccess  = ResultSuccess
	outcomeFail     = ResultFail
	outcomeRedirect = ResultRedirect
	outcomeError    = ResultError
	outcomePass     = ResultPass
)

// Context is handed to a Strategy for the duration of a single authentication
// attempt. The strategy reports its result by calling one of the outcome
// methods below.
type Context struct {
	// Options carries the options passed to Authenticate for this attempt.
	Options *Options

	// Writer is the response writer, available for strategies that need to
	// set headers (e.g. WWW-Authenticate) or write a challenge directly.
	Writer http.ResponseWriter

	result    outcome
	user      any
	info      any    // optional info object attached on success/fail
	challenge string // challenge message on failure
	www       bool   // challenge is a WWW-Authenticate header value, not a message
	status    int    // HTTP status for failure/redirect
	location  string // redirect target
	err       error
}

// Success records that authentication succeeded and yields the given user.
// The optional info value is attached and made available to the caller.
func (c *Context) Success(user any, info ...any) {
	c.result = outcomeSuccess
	c.user = user
	if len(info) > 0 {
		c.info = info[0]
	}
}

// Fail records that authentication failed. challenge is an optional
// human-readable message (e.g. "Invalid credentials") — NOT an HTTP
// WWW-Authenticate value, so it is never emitted as a WWW-Authenticate header;
// status defaults to 401 when zero. This mirrors Passport.js, where a strategy
// that calls this.fail() with a non-string (object) challenge — as
// passport-local does — produces no WWW-Authenticate header. HTTP
// authentication strategies (Basic, Bearer, Digest) that must advertise a
// challenge should call FailWithChallenge instead.
func (c *Context) Fail(challenge string, status int) {
	c.result = outcomeFail
	c.challenge = challenge
	c.www = false
	if status == 0 {
		status = http.StatusUnauthorized
	}
	c.status = status
}

// FailWithChallenge records an authentication failure whose challenge is an HTTP
// WWW-Authenticate header value (RFC 7235), such as `Basic realm="…"` or
// `Digest realm="…", nonce="…", qop="auth"`. Unlike Fail, the challenge here is
// emitted as a WWW-Authenticate response header — but only when the failure is
// actually rendered as a 401 (a configured FailureRedirect diverts it first,
// and no header is sent). This mirrors Passport.js, whose middleware sets
// WWW-Authenticate only for string challenges when the response status is 401.
func (c *Context) FailWithChallenge(challenge string, status int) {
	c.Fail(challenge, status)
	c.www = true
}

// Redirect records that the strategy wants to redirect the user agent (for
// example, to an external identity provider). status defaults to 302.
func (c *Context) Redirect(location string, status int) {
	c.result = outcomeRedirect
	c.location = location
	if status == 0 {
		status = http.StatusFound
	}
	c.status = status
}

// Error records an internal error that occurred during authentication.
func (c *Context) Error(err error) {
	c.result = outcomeError
	c.err = err
}

// Pass records that the strategy declines to handle the request, deferring to
// whatever comes next in the middleware chain.
func (c *Context) Pass() {
	c.result = outcomePass
}

// Result reports which outcome method the strategy called, if any. It is
// primarily useful for unit-testing strategies.
func (c *Context) Result() Result { return c.result }

// SuccessUser returns the user recorded by Success, or nil.
func (c *Context) SuccessUser() any { return c.user }

// Info returns the optional info value recorded alongside Success/Fail.
func (c *Context) Info() any { return c.info }

// Challenge returns the failure challenge message, if any.
func (c *Context) Challenge() string { return c.challenge }

// Err returns the error recorded by Error, if any.
func (c *Context) Err() error { return c.err }
