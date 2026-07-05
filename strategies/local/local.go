// Package local implements the username-and-password authentication strategy,
// a Go port of passport-local. Credentials are read from the request body
// (form-encoded or JSON) and verified by a user-supplied VerifyFunc.
package local

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/malcolmston/passport"
)

// ErrInvalidCredentials is a convenience sentinel a VerifyFunc may return to
// signal that the supplied credentials were wrong. It is treated as an
// authentication failure (not an internal error).
var ErrInvalidCredentials = errors.New("invalid credentials")

// VerifyFunc validates a username/password pair. It should return the
// authenticated user on success, (nil, nil) or (nil, ErrInvalidCredentials) on
// bad credentials, and (nil, err) for an unexpected internal error.
type VerifyFunc func(username, password string) (user any, err error)

// VerifyFuncReq is like VerifyFunc but also receives the request. It mirrors
// passport-local's passReqToCallback option, allowing the verify function to
// read request-scoped data (headers, cookies, context) during verification.
type VerifyFuncReq func(r *http.Request, username, password string) (user any, err error)

// Strategy authenticates requests with a username and password.
type Strategy struct {
	// UsernameField names the request field holding the username. It
	// defaults to "username".
	UsernameField string
	// PasswordField names the request field holding the password. It
	// defaults to "password".
	PasswordField string

	verify    VerifyFunc
	verifyReq VerifyFuncReq
}

// New creates a local Strategy with the default field names.
func New(verify VerifyFunc) *Strategy {
	return &Strategy{
		UsernameField: "username",
		PasswordField: "password",
		verify:        verify,
	}
}

// NewWithRequest creates a local Strategy whose verify receives the
// *http.Request (passport-local's passReqToCallback: true).
func NewWithRequest(verify VerifyFuncReq) *Strategy {
	return &Strategy{
		UsernameField: "username",
		PasswordField: "password",
		verifyReq:     verify,
	}
}

// Name returns the strategy's registration name, "local".
func (s *Strategy) Name() string { return "local" }

// Authenticate implements passport.Strategy.
func (s *Strategy) Authenticate(c *passport.Context, r *http.Request) {
	username, password := s.credentials(r)
	if username == "" || password == "" {
		c.Fail("Missing credentials", http.StatusBadRequest)
		return
	}

	user, err := s.runVerify(r, username, password)
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

// runVerify dispatches to whichever verify function was configured.
func (s *Strategy) runVerify(r *http.Request, username, password string) (any, error) {
	if s.verifyReq != nil {
		return s.verifyReq(r, username, password)
	}
	return s.verify(username, password)
}

// credentials extracts the username and password from the request, supporting
// form-encoded bodies, query parameters, and JSON bodies.
func (s *Strategy) credentials(r *http.Request) (string, string) {
	ct := strings.ToLower(r.Header.Get("Content-Type"))
	if strings.Contains(ct, "application/json") {
		return s.jsonCredentials(r)
	}
	// ParseForm populates r.Form from the query string and a urlencoded body.
	_ = r.ParseForm()
	return r.FormValue(s.UsernameField), r.FormValue(s.PasswordField)
}

func (s *Strategy) jsonCredentials(r *http.Request) (string, string) {
	if r.Body == nil {
		return "", ""
	}
	data, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	r.Body.Close()
	if err != nil {
		return "", ""
	}
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		return "", ""
	}
	username, _ := m[s.UsernameField].(string)
	password, _ := m[s.PasswordField].(string)
	return username, password
}
