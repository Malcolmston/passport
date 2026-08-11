// Package pkce implements Proof Key for Code Exchange (PKCE, RFC 7636) for the
// passport port. PKCE hardens the OAuth 2.0 authorization-code grant against
// authorization-code interception attacks and is mandatory for public clients
// (native and single-page apps). The strategies/oauth2 base deliberately omits
// PKCE; this package supplies the missing primitives so callers can layer it on
// top of any OAuth2 provider preset.
//
// The flow adds two values to the standard authorization-code exchange. Before
// redirecting the user agent to the provider, the client generates a high-
// entropy, URL-safe code verifier and derives a code challenge from it. The
// challenge (and the transformation method, "S256" or "plain") travels on the
// authorization request; the raw verifier is retained locally. When the
// provider redirects back with an authorization code, the client sends the
// verifier along with the code to the token endpoint, and the server confirms
// that the previously seen challenge matches the transformed verifier.
//
// Everything here depends only on the standard library and is deterministic
// except for GenerateVerifier and VerifierWithLength, which draw from
// crypto/rand. The S256 transform is validated against the worked example in
// RFC 7636 Appendix B.
package pkce

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
)

// Method identifies a PKCE code-challenge transformation.
type Method string

const (
	// MethodS256 is the SHA-256 transformation: challenge =
	// BASE64URL(SHA256(ASCII(verifier))). It is REQUIRED by RFC 7636 and
	// should be preferred whenever the client can compute a SHA-256 digest.
	MethodS256 Method = "S256"

	// MethodPlain is the identity transformation: challenge = verifier. It
	// exists only for clients that cannot perform SHA-256 and offers no
	// interception protection on its own.
	MethodPlain Method = "plain"
)

// minVerifierLen and maxVerifierLen bound the number of raw random bytes used
// to build a verifier. RFC 7636 requires the resulting verifier string to be
// 43-128 characters; base64url encoding expands n bytes to ceil(4n/3)
// characters, so 32..96 input bytes stay within the legal window.
const (
	pkceMinVerifierBytes = 32
	pkceMaxVerifierBytes = 96
)

// String returns the wire representation of the method ("S256" or "plain").
func (m Method) String() string { return string(m) }

// Valid reports whether m is one of the two RFC 7636 transformations.
func (m Method) Valid() bool { return m == MethodS256 || m == MethodPlain }

// GenerateVerifier returns a cryptographically random code verifier built from
// 32 bytes of entropy, yielding a 43-character URL-safe string — the shortest
// verifier RFC 7636 permits. The error is non-nil only if the system random
// source fails.
func GenerateVerifier() (string, error) {
	return VerifierWithLength(pkceMinVerifierBytes)
}

// VerifierWithLength returns a random code verifier derived from n bytes of
// entropy. n must be between 32 and 96 inclusive so that the base64url-encoded
// result lands within the 43-128 character range required by RFC 7636.
func VerifierWithLength(n int) (string, error) {
	if n < pkceMinVerifierBytes || n > pkceMaxVerifierBytes {
		return "", fmt.Errorf("pkce: verifier entropy %d bytes out of range [%d,%d]", n, pkceMinVerifierBytes, pkceMaxVerifierBytes)
	}
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("pkce: reading random source: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// ValidVerifier reports whether v is a syntactically valid code verifier: 43 to
// 128 characters drawn from the unreserved set [A-Za-z0-9-._~].
func ValidVerifier(v string) bool {
	if len(v) < 43 || len(v) > 128 {
		return false
	}
	for i := 0; i < len(v); i++ {
		c := v[i]
		switch {
		case c >= 'A' && c <= 'Z':
		case c >= 'a' && c <= 'z':
		case c >= '0' && c <= '9':
		case c == '-' || c == '.' || c == '_' || c == '~':
		default:
			return false
		}
	}
	return true
}

// S256Challenge returns the SHA-256 code challenge for verifier:
// BASE64URL-ENCODE(SHA256(ASCII(verifier))), without padding.
func S256Challenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// PlainChallenge returns the "plain" code challenge, which is the verifier
// unchanged.
func PlainChallenge(verifier string) string { return verifier }

// ComputeChallenge derives the code challenge for verifier under method. It
// returns an error if method is not a recognized PKCE transformation.
func ComputeChallenge(method Method, verifier string) (string, error) {
	switch method {
	case MethodS256:
		return S256Challenge(verifier), nil
	case MethodPlain:
		return PlainChallenge(verifier), nil
	default:
		return "", fmt.Errorf("pkce: unknown method %q", method)
	}
}

// Verify reports whether verifier matches challenge under method, using a
// constant-time comparison. It returns false for an unrecognized method, an
// empty challenge, or a verifier that is not syntactically valid per
// ValidVerifier.
//
// The syntax check is load-bearing, not cosmetic. RFC 7636 Section 4.6 requires
// the server to validate the verifier it receives, and under MethodPlain the
// challenge is the verifier: without the check, a request presenting an empty
// verifier against a stored empty challenge would "match" and defeat PKCE
// entirely. Rejecting anything shorter than 43 characters also enforces the
// entropy floor the RFC mandates.
func Verify(method Method, verifier, challenge string) bool {
	if challenge == "" || !ValidVerifier(verifier) {
		return false
	}
	computed, err := ComputeChallenge(method, verifier)
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(computed), []byte(challenge)) == 1
}

// ParseMethod interprets a code_challenge_method value from an authorization
// request. RFC 7636 Section 4.3 specifies that an absent method means "plain",
// so an empty string yields MethodPlain; any value other than the two defined
// transformations is an error. The comparison is case-sensitive, as the RFC
// defines both names as literals.
func ParseMethod(s string) (Method, error) {
	switch Method(s) {
	case "":
		return MethodPlain, nil
	case MethodS256:
		return MethodS256, nil
	case MethodPlain:
		return MethodPlain, nil
	default:
		return "", fmt.Errorf("pkce: unknown code_challenge_method %q", s)
	}
}

// Pair bundles a verifier with its derived challenge and the transformation
// method that connects them.
type Pair struct {
	Verifier  string // the secret code verifier, kept by the client
	Challenge string // the public code challenge, sent on the authorization request
	Method    Method // the transformation linking verifier to challenge
}

// New returns a fresh Pair using the S256 transformation. The verifier is
// randomly generated; the challenge is derived from it.
func New() (Pair, error) {
	v, err := GenerateVerifier()
	if err != nil {
		return Pair{}, err
	}
	return Pair{Verifier: v, Challenge: S256Challenge(v), Method: MethodS256}, nil
}

// NewWithMethod returns a fresh Pair using the given transformation.
//
// Callers should pass MethodS256 unless they are talking to a server that
// genuinely cannot do SHA-256: under MethodPlain the challenge is the verifier
// in cleartext, so anything that can observe the authorization request also
// learns the secret and PKCE stops protecting against code interception. RFC
// 7636 Section 4.2 requires clients capable of S256 to use it.
func NewWithMethod(method Method) (Pair, error) {
	if !method.Valid() {
		return Pair{}, fmt.Errorf("pkce: unknown method %q", method)
	}
	v, err := GenerateVerifier()
	if err != nil {
		return Pair{}, err
	}
	challenge, err := ComputeChallenge(method, v)
	if err != nil {
		return Pair{}, err
	}
	return Pair{Verifier: v, Challenge: challenge, Method: method}, nil
}

// AuthParams returns the query parameters a client adds to the authorization
// request: code_challenge and code_challenge_method.
func (p Pair) AuthParams() map[string]string {
	return map[string]string{
		"code_challenge":        p.Challenge,
		"code_challenge_method": p.Method.String(),
	}
}

// TokenParams returns the form parameters a client adds to the authorization-
// code token request: the single code_verifier field (RFC 7636 Section 4.5).
// The verifier is a secret and must travel only on that back-channel POST,
// never on the front-channel authorization request.
func (p Pair) TokenParams() map[string]string {
	return map[string]string{"code_verifier": p.Verifier}
}

// Valid reports whether p is internally consistent: the verifier is
// syntactically legal and the challenge is exactly what Method derives from it.
func (p Pair) Valid() bool {
	return Verify(p.Method, p.Verifier, p.Challenge)
}
