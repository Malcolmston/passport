// Package httpauth encodes and decodes HTTP Authorization and
// WWW-Authenticate headers for the passport port. The basic, bearer, and digest
// strategies each parse these headers themselves; this package factors the
// wire-format handling into one standard-library-only place with exact,
// specification-driven behavior.
//
// It covers the two most common schemes: HTTP Basic (RFC 7617), whose
// credential is base64("user:pass"), and Bearer (RFC 6750). It also builds the
// WWW-Authenticate challenge servers return with a 401, including the realm and
// (for Bearer) an optional error code. Everything here is deterministic.
package httpauth

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
)

// Errors returned when a header cannot be parsed.
var (
	// ErrNoHeader indicates an empty Authorization header.
	ErrNoHeader = errors.New("httpauth: empty authorization header")
	// ErrWrongScheme indicates the header used a scheme other than the one
	// requested.
	ErrWrongScheme = errors.New("httpauth: unexpected authorization scheme")
	// ErrMalformed indicates the header value was structurally invalid.
	ErrMalformed = errors.New("httpauth: malformed authorization header")
)

// Scheme names an HTTP authentication scheme.
const (
	SchemeBasic  = "Basic"
	SchemeBearer = "Bearer"
)

// ParseScheme splits an Authorization header value into its scheme token and
// the remaining credentials, without interpreting the credentials. The scheme
// is returned as written (callers should compare case-insensitively).
func ParseScheme(header string) (scheme, rest string, err error) {
	header = strings.TrimSpace(header)
	if header == "" {
		return "", "", ErrNoHeader
	}
	parts := strings.SplitN(header, " ", 2)
	if len(parts) != 2 || parts[1] == "" {
		return "", "", ErrMalformed
	}
	return parts[0], strings.TrimSpace(parts[1]), nil
}

// BasicCredentials holds a decoded HTTP Basic username and password.
type BasicCredentials struct {
	Username string
	Password string
}

// EncodeBasic returns the full "Basic <base64>" Authorization header value for
// the given username and password, per RFC 7617.
func EncodeBasic(username, password string) string {
	raw := username + ":" + password
	return SchemeBasic + " " + base64.StdEncoding.EncodeToString([]byte(raw))
}

// ParseBasic decodes an "Authorization: Basic ..." header into its username and
// password. It returns ErrWrongScheme for a non-Basic header and ErrMalformed
// if the base64 payload is invalid or lacks the ":" separator.
func ParseBasic(header string) (BasicCredentials, error) {
	scheme, rest, err := ParseScheme(header)
	if err != nil {
		return BasicCredentials{}, err
	}
	if !strings.EqualFold(scheme, SchemeBasic) {
		return BasicCredentials{}, ErrWrongScheme
	}
	decoded, err := base64.StdEncoding.DecodeString(rest)
	if err != nil {
		return BasicCredentials{}, ErrMalformed
	}
	i := strings.IndexByte(string(decoded), ':')
	if i < 0 {
		return BasicCredentials{}, ErrMalformed
	}
	return BasicCredentials{Username: string(decoded[:i]), Password: string(decoded[i+1:])}, nil
}

// EncodeBearer returns the "Bearer <token>" Authorization header value for
// token, per RFC 6750.
func EncodeBearer(token string) string { return SchemeBearer + " " + token }

// ParseBearer extracts the token from an "Authorization: Bearer ..." header. It
// returns ErrWrongScheme for a non-Bearer header.
func ParseBearer(header string) (string, error) {
	scheme, rest, err := ParseScheme(header)
	if err != nil {
		return "", err
	}
	if !strings.EqualFold(scheme, SchemeBearer) {
		return "", ErrWrongScheme
	}
	return rest, nil
}

// SchemeOf returns the lower-cased authentication scheme named by an
// Authorization header value, or "" if the header is empty or malformed.
func SchemeOf(header string) string {
	scheme, _, err := ParseScheme(header)
	if err != nil {
		return ""
	}
	return strings.ToLower(scheme)
}

// HasScheme reports whether an Authorization header uses the given scheme,
// compared case-insensitively.
func HasScheme(header, scheme string) bool {
	s, _, err := ParseScheme(header)
	return err == nil && strings.EqualFold(s, scheme)
}

// BasicChallenge returns the WWW-Authenticate header value a server sends with a
// 401 to request HTTP Basic credentials for realm.
func BasicChallenge(realm string) string {
	return fmt.Sprintf(`Basic realm=%q`, realm)
}

// BearerChallenge returns the WWW-Authenticate header value for a Bearer 401.
// When realm is non-empty it is included; when errCode is non-empty an RFC 6750
// error parameter (e.g. "invalid_token") is appended.
func BearerChallenge(realm, errCode string) string {
	var b strings.Builder
	b.WriteString(SchemeBearer)
	sep := " "
	if realm != "" {
		fmt.Fprintf(&b, `%srealm=%q`, sep, realm)
		sep = ", "
	}
	if errCode != "" {
		fmt.Fprintf(&b, `%serror=%q`, sep, errCode)
	}
	return b.String()
}
