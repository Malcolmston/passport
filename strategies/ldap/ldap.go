// Package ldap implements a username/password authentication strategy whose
// credential check is an LDAP "bind" operation, a standard-library-only port in
// the spirit of passport-ldapauth. Instead of comparing a password against a
// local store, it authenticates the user by attempting to bind to a directory
// server as that user — the canonical way to verify credentials against LDAP or
// Active Directory.
//
// Use this strategy when your users live in a corporate directory and you want
// them to sign in with their directory username and password. Like the local
// strategy it reads credentials from a submitted HTML form (fields default to
// "username" and "password", overridable via UserField and PassField) and
// establishes a passport session on success, so it slots into the same form-post
// login route.
//
// The flow is: read the username and password from the form, expand the username
// into a distinguished name (DN) using DNTemplate, and call the configured Bind
// function with that DN and the presented password. DNTemplate is a fmt template
// with a single %s for the username (for example
// "uid=%s,ou=people,dc=example,dc=com"); when empty the raw username is used as
// the DN. A request missing either credential fails with an HTTP 401 before Bind
// is called, and a nil Bind is reported as an internal error.
//
// SIMPLIFIED: performing a real network LDAP bind requires an LDAP client
// library, which is out of scope for this dependency-free port. The actual bind
// is therefore delegated to the caller-supplied Bind function, which is the
// single integration point where a real LDAP dial belongs — this is where you
// connect to your directory host, negotiate TLS/StartTLS, and perform the bind
// (and typically a search to load the user's attributes). Binding with an empty
// password must be rejected there, since many servers treat it as an anonymous
// bind that unexpectedly succeeds.
//
// The Bind contract follows the rest of this port: return a non-nil user on a
// successful bind to establish the session; return (nil, nil) or
// (nil, ErrInvalidCredentials) to reject the login as an HTTP 401 failure; and
// return (nil, otherErr) for an unexpected error (a connection failure, say),
// which passport surfaces via Context.Error. The ErrInvalidCredentials sentinel
// lets a failed bind be distinguished from a genuine fault.
package ldap

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/malcolmston/passport"
)

// ErrInvalidCredentials is a convenience sentinel a Bind func may return to
// signal a failed bind (treated as an authentication failure, not an error).
var ErrInvalidCredentials = errors.New("ldap: invalid credentials")

// BindFunc performs the LDAP bind. It receives the computed DN and the
// presented password and returns the authenticated user on success. Return
// (nil, nil) or (nil, ErrInvalidCredentials) to reject; (nil, otherErr) for an
// internal error.
type BindFunc func(dn, password string) (user any, err error)

// Options configures the strategy.
type Options struct {
	// Bind performs the bind. Required.
	Bind BindFunc
	// DNTemplate is a fmt template with a single %s for the username, e.g.
	// "uid=%s,ou=people,dc=example,dc=com". When empty the raw username is
	// used as the DN.
	DNTemplate string
	// UserField is the form field holding the username. Defaults to "username".
	UserField string
	// PassField is the form field holding the password. Defaults to "password".
	PassField string
}

// Strategy authenticates via an LDAP bind.
type Strategy struct {
	opts Options
}

// New creates a Strategy from opts.
func New(opts Options) *Strategy {
	if opts.UserField == "" {
		opts.UserField = "username"
	}
	if opts.PassField == "" {
		opts.PassField = "password"
	}
	return &Strategy{opts: opts}
}

// Name returns "ldap".
func (s *Strategy) Name() string { return "ldap" }

// DN expands username into a distinguished name using DNTemplate.
func (s *Strategy) DN(username string) string {
	if s.opts.DNTemplate == "" {
		return username
	}
	return fmt.Sprintf(s.opts.DNTemplate, username)
}

// Authenticate implements passport.Strategy.
func (s *Strategy) Authenticate(c *passport.Context, r *http.Request) {
	if s.opts.Bind == nil {
		c.Error(errors.New("ldap: no Bind function configured"))
		return
	}
	_ = r.ParseForm()
	username := r.FormValue(s.opts.UserField)
	password := r.FormValue(s.opts.PassField)
	if username == "" || password == "" {
		c.Fail("Missing credentials", http.StatusUnauthorized)
		return
	}

	user, err := s.opts.Bind(s.DN(username), password)
	if err != nil {
		if errors.Is(err, ErrInvalidCredentials) {
			c.Fail("Invalid credentials", http.StatusUnauthorized)
			return
		}
		c.Error(err)
		return
	}
	if user == nil {
		c.Fail("Invalid credentials", http.StatusUnauthorized)
		return
	}
	c.Success(user)
}
