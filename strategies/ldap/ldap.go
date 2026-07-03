// Package ldap implements a username/password strategy whose credential check
// is an LDAP "bind" operation.
//
// SIMPLIFIED: performing a real network LDAP bind requires an LDAP client
// library, which is out of scope for this standard-library-only port. Instead,
// the actual bind is delegated to a caller-supplied Bind function: this package
// reads the username and password from the request form, expands the username
// into a distinguished name (DN) using DNTemplate, and calls Bind(dn, password).
// Bind is the single integration point where a real LDAP dial belongs.
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
