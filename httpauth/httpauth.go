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
	"crypto/subtle"
	"encoding/base64"
	"errors"
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
//
// Per RFC 7235 Section 2.1 the scheme and credentials are separated by one or
// more SP characters — "Basic  dXNlcjpwdw" parses the same as the single-space
// form — and by nothing else: a horizontal tab is not a legal separator, so
// "Basic\tdXNlcjpwdw" is ErrMalformed. Being lenient there would only create a
// parser differential with the proxies and gateways in front of the
// application, which follow the grammar. Surrounding whitespace on the field
// value itself is insignificant per RFC 7230 and is trimmed.
//
// A header with no separator, or with an empty credentials part, is
// ErrMalformed; an empty header is ErrNoHeader.
func ParseScheme(header string) (scheme, rest string, err error) {
	header = strings.Trim(header, " \t")
	if header == "" {
		return "", "", ErrNoHeader
	}
	i := strings.IndexByte(header, ' ')
	if i < 0 {
		return "", "", ErrMalformed
	}
	scheme = header[:i]
	rest = strings.Trim(header[i+1:], " \t")
	if scheme == "" || rest == "" {
		return "", "", ErrMalformed
	}
	return scheme, rest, nil
}

// SecureCompare reports whether a and b are equal using a constant-time
// comparison. Use it instead of == whenever one of the operands is a secret —
// a password, an API key, a signature — so the check does not leak how many
// leading bytes matched through response timing.
//
// Note that, like crypto/subtle.ConstantTimeCompare, this does not hide the
// operands' lengths.
func SecureCompare(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// BasicCredentials holds a decoded HTTP Basic username and password.
type BasicCredentials struct {
	Username string
	Password string
}

// Matches reports whether c carries exactly the given username and password,
// comparing both in constant time so a caller cannot be used as an oracle for
// guessing either field one byte at a time. Both fields are always compared,
// even when the username already differs, so the timing does not reveal which
// of the two was wrong.
//
// This is only appropriate for a fixed, in-process credential pair (a metrics
// endpoint, an internal callback). Multi-user systems should look the user up
// and compare the password against a password hash instead.
func (c BasicCredentials) Matches(username, password string) bool {
	userOK := subtle.ConstantTimeCompare([]byte(c.Username), []byte(username))
	passOK := subtle.ConstantTimeCompare([]byte(c.Password), []byte(password))
	return userOK&passOK == 1
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
//
// The payload is split at the first ":" only, so a password may itself contain
// colons (RFC 7617 forbids them in the user-id but not in the password).
// Padded and unpadded base64 are both accepted, since some clients omit the
// "=" padding.
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
		decoded, err = base64.RawStdEncoding.DecodeString(rest)
	}
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

// QuoteString renders s as an RFC 7230 quoted-string suitable for use as an
// auth-param value in a WWW-Authenticate header. Backslashes and double quotes
// are escaped, and CR, LF, NUL and other control characters are dropped so an
// attacker-influenced realm cannot terminate the value or inject a second
// header (response splitting).
func QuoteString(s string) string {
	var b strings.Builder
	b.Grow(len(s) + 2)
	b.WriteByte('"')
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c < 0x20 || c == 0x7f:
			// Control characters (including CR and LF) have no legal
			// quoted-string representation; drop them.
		case c == '"' || c == '\\':
			b.WriteByte('\\')
			b.WriteByte(c)
		default:
			b.WriteByte(c)
		}
	}
	b.WriteByte('"')
	return b.String()
}

// BasicChallenge returns the WWW-Authenticate header value a server sends with a
// 401 to request HTTP Basic credentials for realm. The realm is emitted as a
// quoted-string via QuoteString, so it cannot break out of the header value.
func BasicChallenge(realm string) string {
	return SchemeBasic + " realm=" + QuoteString(realm)
}

// BearerChallenge returns the WWW-Authenticate header value for a Bearer 401.
// When realm is non-empty it is included; when errCode is non-empty an RFC 6750
// error parameter (e.g. "invalid_token") is appended. Both are emitted as
// quoted-strings via QuoteString.
func BearerChallenge(realm, errCode string) string {
	var b strings.Builder
	b.WriteString(SchemeBearer)
	sep := " "
	if realm != "" {
		b.WriteString(sep + "realm=" + QuoteString(realm))
		sep = ", "
	}
	if errCode != "" {
		b.WriteString(sep + "error=" + QuoteString(errCode))
	}
	return b.String()
}
