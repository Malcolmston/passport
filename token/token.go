// Package token generates and compares opaque security tokens for the passport
// port. Several strategies — bearer tokens, API keys, magic links, "remember
// me" cookies — need unpredictable, URL-safe identifiers and a timing-safe way
// to check them. Each of those packages currently rolls its own; this package
// centralizes the primitives so they share one audited, standard-library-only
// implementation.
//
// Generation always draws from crypto/rand and fails closed: any shortfall from
// the system entropy source is returned as an error rather than silently
// producing a weak token. Comparison uses crypto/subtle for constant-time
// equality, avoiding the timing side channels that a plain string compare would
// leak. Token lengths are expressed in bytes of entropy; the encoded strings
// are longer.
package token

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"fmt"
)

// DefaultEntropyBytes is the entropy used by the convenience constructors that
// do not take an explicit size. 32 bytes (256 bits) is a comfortable margin
// against brute force.
const DefaultEntropyBytes = 32

// Bytes returns n cryptographically random bytes. It returns an error if the
// system random source cannot supply them.
func Bytes(n int) ([]byte, error) {
	if n <= 0 {
		return nil, fmt.Errorf("token: byte count must be positive, got %d", n)
	}
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return nil, fmt.Errorf("token: reading random source: %w", err)
	}
	return buf, nil
}

// Hex returns a random token of n bytes of entropy encoded as a lower-case hex
// string of length 2n.
func Hex(n int) (string, error) {
	b, err := Bytes(n)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// URLSafe returns a random token of n bytes of entropy encoded with unpadded
// base64url, safe for use in URLs, cookies, and headers.
func URLSafe(n int) (string, error) {
	b, err := Bytes(n)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// New returns a URL-safe token with DefaultEntropyBytes of entropy.
func New() (string, error) { return URLSafe(DefaultEntropyBytes) }

// MustNew returns a URL-safe token like New but panics if the system random
// source fails. It suits package-level initialization where an entropy failure
// is unrecoverable and should crash the program rather than yield a weak token.
func MustNew() string {
	t, err := New()
	if err != nil {
		panic(err)
	}
	return t
}

// Numeric returns a random decimal string of exactly n digits, suitable for
// short verification codes. Leading zeros are preserved. It draws rejection-
// sampled random digits so the distribution is uniform.
func Numeric(n int) (string, error) {
	if n <= 0 {
		return "", fmt.Errorf("token: digit count must be positive, got %d", n)
	}
	out := make([]byte, n)
	buf := make([]byte, 1)
	for i := 0; i < n; {
		if _, err := rand.Read(buf); err != nil {
			return "", fmt.Errorf("token: reading random source: %w", err)
		}
		// Reject values in [250,255] so the remaining 250 map uniformly to
		// 0-9 (250 = 25*10).
		if buf[0] >= 250 {
			continue
		}
		out[i] = '0' + buf[0]%10
		i++
	}
	return string(out), nil
}

// Equal reports whether a and b are the same token using a constant-time
// comparison, so callers do not leak length-independent timing information when
// checking a secret.
func Equal(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
