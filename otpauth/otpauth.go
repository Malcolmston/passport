// Package otpauth builds and parses "otpauth://" key URIs for the passport
// port. These URIs are the de-facto interchange format for provisioning
// time-based (TOTP) and counter-based (HOTP) one-time-password secrets into
// authenticator apps, most commonly by encoding them in a QR code. The passport
// TOTP and HOTP strategies verify codes but ship no way to describe an
// enrollment; this package provides that missing piece, following the Google
// Authenticator Key Uri Format.
//
// A Key captures the OTP type (totp or hotp), the account label and issuer, the
// shared secret, and the algorithm/digits parameters. URL renders it to a
// canonical otpauth URI and Parse reads one back; the two round-trip. Secrets
// are handled as base32 without padding, the encoding authenticator apps expect.
// Everything here is deterministic and uses only the standard library, except
// GenerateSecret which draws from crypto/rand.
//
// A Key can also produce and check the codes it describes. Code implements the
// RFC 4226 HOTP construction and its RFC 6238 time-based variant, honoring
// everything the Key Uri Format can express — SHA-1, SHA-256 or SHA-512, six to
// ten digits, an arbitrary time step — which is strictly more than the fixed
// SHA-1/6-digit/30-second strategies in strategies/totp and strategies/hotp can
// handle. Verify checks a submitted code against an acceptance window, forward-
// only for HOTP so a consumed counter can never be replayed, and symmetric for
// TOTP so honest clock drift is tolerated; every candidate is compared in
// constant time. Both are validated against the published test vectors in RFC
// 4226 Appendix D and RFC 6238 Appendix B.
package otpauth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Type is the OTP algorithm family: time-based or counter-based.
type Type string

const (
	// TOTP is the time-based one-time-password type (RFC 6238).
	TOTP Type = "totp"
	// HOTP is the HMAC-based counter one-time-password type (RFC 4226).
	HOTP Type = "hotp"
)

// Key describes a single OTP credential in the otpauth key-URI model.
type Key struct {
	Type      Type   // totp or hotp
	Issuer    string // the provider or site name, e.g. "Example, Inc."
	Account   string // the account label, typically an email or username
	Secret    string // the shared secret, base32-encoded without padding
	Algorithm string // HMAC hash: SHA1 (default), SHA256, or SHA512
	Digits    int    // number of code digits (default 6)
	Period    int    // TOTP time step in seconds (default 30; ignored for HOTP)
	Counter   uint64 // HOTP initial counter (ignored for TOTP)
}

// GenerateSecret returns a random base32 secret string (no padding) built from
// n bytes of entropy. Twenty bytes is a common, well-supported choice.
func GenerateSecret(n int) (string, error) {
	if n <= 0 {
		return "", fmt.Errorf("otpauth: secret byte count must be positive, got %d", n)
	}
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("otpauth: reading random source: %w", err)
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(buf), nil
}

func (k Key) algorithm() string {
	if k.Algorithm == "" {
		return "SHA1"
	}
	return strings.ToUpper(k.Algorithm)
}

func (k Key) digits() int {
	if k.Digits == 0 {
		return 6
	}
	return k.Digits
}

func (k Key) period() int {
	if k.Period == 0 {
		return 30
	}
	return k.Period
}

// Label returns the canonical "Issuer:Account" label, or just Account when no
// issuer is set.
func (k Key) Label() string {
	if k.Issuer != "" {
		return k.Issuer + ":" + k.Account
	}
	return k.Account
}

// URL renders the Key as a canonical otpauth URI string. The issuer is written
// both as a label prefix and as an explicit issuer parameter, as recommended by
// the Key Uri Format.
func (k Key) URL() string {
	v := url.Values{}
	v.Set("secret", k.Secret)
	if k.Issuer != "" {
		v.Set("issuer", k.Issuer)
	}
	v.Set("algorithm", k.algorithm())
	v.Set("digits", strconv.Itoa(k.digits()))
	if k.Type == HOTP {
		v.Set("counter", strconv.FormatUint(k.Counter, 10))
	} else {
		v.Set("period", strconv.Itoa(k.period()))
	}
	u := url.URL{
		Scheme: "otpauth",
		Host:   string(k.Type),
		Path:   "/" + k.Label(),
		// url.Values.Encode encodes spaces as "+", but the Key Uri Format is
		// canonically "%20" in the query too; some authenticator apps render a
		// literal "+" verbatim. Encode escapes any literal "+" as "%2B", so
		// every "+" it emits is a space and this replacement is lossless.
		RawQuery: strings.ReplaceAll(v.Encode(), "+", "%20"),
	}
	return u.String()
}

// Parse reads an otpauth URI into a Key, applying the format's defaults
// (SHA1, 6 digits, 30-second period) for any omitted parameters. It returns an
// error if the scheme, type, or secret is missing or malformed.
func Parse(raw string) (Key, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return Key{}, fmt.Errorf("otpauth: parsing URI: %w", err)
	}
	if u.Scheme != "otpauth" {
		return Key{}, fmt.Errorf("otpauth: scheme %q is not otpauth", u.Scheme)
	}
	typ := Type(strings.ToLower(u.Host))
	if typ != TOTP && typ != HOTP {
		return Key{}, fmt.Errorf("otpauth: unknown type %q", u.Host)
	}
	q := u.Query()
	k := Key{
		Type:      typ,
		Secret:    q.Get("secret"),
		Issuer:    q.Get("issuer"),
		Algorithm: strings.ToUpper(q.Get("algorithm")),
	}
	if k.Secret == "" {
		return Key{}, fmt.Errorf("otpauth: missing secret")
	}
	// The secret is the whole credential, so a URI carrying one that is not
	// decodable base32 is rejected here rather than accepted and then failing
	// later inside Code, where the caller has already stored the enrollment.
	if _, err := DecodeSecret(k.Secret); err != nil {
		return Key{}, err
	}
	label := strings.TrimPrefix(u.Path, "/")
	if i := strings.Index(label, ":"); i >= 0 {
		issuer := strings.TrimSpace(label[:i])
		k.Account = strings.TrimSpace(label[i+1:])
		if k.Issuer == "" {
			k.Issuer = issuer
		}
	} else {
		k.Account = label
	}
	if k.Algorithm == "" {
		k.Algorithm = "SHA1"
	}
	if d := q.Get("digits"); d != "" {
		if k.Digits, err = strconv.Atoi(d); err != nil {
			return Key{}, fmt.Errorf("otpauth: invalid digits %q", d)
		}
		// A zero, negative, or absurd digit count would otherwise be carried
		// into Code, where it silently produces an unusable or panicking
		// format width. Reject it at the boundary instead.
		if k.Digits < minDigits || k.Digits > maxDigits {
			return Key{}, fmt.Errorf("otpauth: digits %d out of range [%d,%d]", k.Digits, minDigits, maxDigits)
		}
	} else {
		k.Digits = 6
	}
	if typ == HOTP {
		// The Key Uri Format makes counter REQUIRED for hotp: without it there
		// is no shared starting point, and silently assuming 0 would hand the
		// server a moving factor the authenticator app never agreed to.
		c := q.Get("counter")
		if c == "" {
			return Key{}, fmt.Errorf("otpauth: hotp URI is missing the required counter parameter")
		}
		if k.Counter, err = strconv.ParseUint(c, 10, 64); err != nil {
			return Key{}, fmt.Errorf("otpauth: invalid counter %q", c)
		}
	} else {
		if p := q.Get("period"); p != "" {
			if k.Period, err = strconv.Atoi(p); err != nil {
				return Key{}, fmt.Errorf("otpauth: invalid period %q", p)
			}
			// A non-positive period would divide by zero (or run backwards)
			// when deriving the TOTP time step.
			if k.Period <= 0 {
				return Key{}, fmt.Errorf("otpauth: period %d must be positive", k.Period)
			}
		} else {
			k.Period = 30
		}
	}
	if _, err := hashFor(k.Algorithm); err != nil {
		return Key{}, err
	}
	return k, nil
}

// DecodeSecret returns the raw bytes of a Key's base32-encoded secret,
// tolerating lower-case input and missing padding.
func DecodeSecret(secret string) ([]byte, error) {
	s := strings.ToUpper(strings.TrimSpace(secret))
	s = strings.ReplaceAll(s, " ", "")
	enc := base32.StdEncoding.WithPadding(base32.NoPadding)
	trimmed := strings.TrimRight(s, "=")
	b, err := enc.DecodeString(trimmed)
	if err != nil {
		return nil, fmt.Errorf("otpauth: decoding base32 secret: %w", err)
	}
	return b, nil
}

// Digit-count bounds. RFC 4226 requires at least six digits and the Key Uri
// Format is only defined for six or eight; the upper bound is where a 31-bit
// dynamic truncation stops adding entropy and starts emitting leading zeros.
const (
	minDigits = 6
	maxDigits = 10
)

// ErrUnknownAlgorithm indicates a Key.Algorithm this package cannot compute.
var ErrUnknownAlgorithm = errors.New("otpauth: unknown algorithm")

// hashFor maps a Key Uri Format algorithm name to its hash constructor. An
// empty name means SHA1, the format's default.
func hashFor(algorithm string) (func() hash.Hash, error) {
	switch strings.ToUpper(strings.TrimSpace(algorithm)) {
	case "", "SHA1":
		return sha1.New, nil
	case "SHA256":
		return sha256.New, nil
	case "SHA512":
		return sha512.New, nil
	default:
		return nil, fmt.Errorf("%w: %q", ErrUnknownAlgorithm, algorithm)
	}
}

// Validate reports whether k is internally consistent and can produce codes: a
// known Type and Algorithm, a decodable base32 Secret, a digit count within
// [6,10], and (for TOTP) a positive Period.
func (k Key) Validate() error {
	if k.Type != TOTP && k.Type != HOTP {
		return fmt.Errorf("otpauth: unknown type %q", k.Type)
	}
	if k.Secret == "" {
		return errors.New("otpauth: missing secret")
	}
	if _, err := DecodeSecret(k.Secret); err != nil {
		return err
	}
	if _, err := hashFor(k.Algorithm); err != nil {
		return err
	}
	if d := k.digits(); d < minDigits || d > maxDigits {
		return fmt.Errorf("otpauth: digits %d out of range [%d,%d]", d, minDigits, maxDigits)
	}
	if k.Type == TOTP && k.period() <= 0 {
		return fmt.Errorf("otpauth: period %d must be positive", k.period())
	}
	return nil
}

// hotp is the RFC 4226 Section 5.3 HOTP construction: HMAC the 8-byte
// big-endian counter under the shared secret, dynamically truncate the digest
// to a 31-bit integer, and take it modulo 10^digits.
func hotp(newH func() hash.Hash, secret []byte, counter uint64, digits int) string {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], counter)

	mac := hmac.New(newH, secret)
	mac.Write(buf[:])
	sum := mac.Sum(nil)

	// Dynamic truncation: the low nibble of the last byte selects the offset
	// of the 4 bytes to extract, and the top bit is masked off so the result
	// is a positive 31-bit integer regardless of hash length.
	offset := sum[len(sum)-1] & 0x0f
	bin := uint32(sum[offset]&0x7f)<<24 |
		uint32(sum[offset+1])<<16 |
		uint32(sum[offset+2])<<8 |
		uint32(sum[offset+3])

	mod := uint64(1)
	for i := 0; i < digits; i++ {
		mod *= 10
	}
	return fmt.Sprintf("%0*d", digits, uint64(bin)%mod)
}

// MovingFactor returns the counter that drives the HOTP construction for this
// Key at time t: k.Counter for an HOTP key (t is ignored), or
// floor(unixSeconds / Period) for a TOTP key (RFC 6238 Section 4.2).
func (k Key) MovingFactor(t time.Time) uint64 { return k.counterAt(t) }

func (k Key) counterAt(t time.Time) uint64 {
	if k.Type == HOTP {
		return k.Counter
	}
	secs := t.Unix()
	if secs < 0 {
		// Go's integer division truncates toward zero, so a pre-epoch time
		// would land one step late; floor it explicitly.
		return uint64((secs - int64(k.period()) + 1) / int64(k.period()))
	}
	return uint64(secs / int64(k.period()))
}

// Code returns the one-time password this Key produces at time t, honoring the
// Key's Algorithm, Digits, and (for TOTP) Period. For a HOTP key the time is
// ignored and the Key's Counter is used as the moving factor.
//
// Unlike the fixed SHA1/6-digit/30-second strategies in strategies/totp and
// strategies/hotp, this respects everything the Key Uri Format can express, so
// it can generate codes for SHA-256 and SHA-512 keys and for 8-digit tokens. It
// returns an error if the Key does not pass Validate.
func (k Key) Code(t time.Time) (string, error) {
	if err := k.Validate(); err != nil {
		return "", err
	}
	secret, err := DecodeSecret(k.Secret)
	if err != nil {
		return "", err
	}
	newH, err := hashFor(k.Algorithm)
	if err != nil {
		return "", err
	}
	return hotp(newH, secret, k.counterAt(t), k.digits()), nil
}

// CodeAtCounter returns the one-time password for an explicit moving factor,
// bypassing the Key's own Counter and Period. It is the building block behind
// Code and is useful for pre-generating a batch of HOTP codes or for driving a
// custom acceptance window.
func (k Key) CodeAtCounter(counter uint64) (string, error) {
	if err := k.Validate(); err != nil {
		return "", err
	}
	secret, err := DecodeSecret(k.Secret)
	if err != nil {
		return "", err
	}
	newH, err := hashFor(k.Algorithm)
	if err != nil {
		return "", err
	}
	return hotp(newH, secret, counter, k.digits()), nil
}

// Verify reports whether code is valid for this Key at time t, accepting any
// code within window moving-factor steps of the expected one, and returns the
// counter that matched.
//
// The window is interpreted per OTP type. For TOTP it is symmetric — window
// steps either side of the current one — because the client and server clocks
// can drift in both directions; window 1 with the default 30-second period
// accepts the previous, current, and next code. For HOTP it looks only forward,
// from the Key's Counter to Counter+window, because a token whose counter has
// fallen behind the server's is not something the server should re-accept; that
// is exactly the replay it must prevent. A window of 0 accepts only the exact
// expected code.
//
// Every candidate is compared with crypto/subtle.ConstantTimeCompare, and all
// candidates are evaluated even after a match, so neither the validity of the
// code nor which step matched leaks through response timing.
//
// Verify does not by itself make a code single-use. TOTP codes stay valid for
// the rest of their step, and HOTP codes stay valid until the stored counter
// advances: on success the caller MUST persist matched+1 as the new counter (or,
// for TOTP, record the accepted step) before honoring another attempt.
func (k Key) Verify(code string, t time.Time, window int) (matched uint64, ok bool) {
	if window < 0 {
		window = 0
	}
	if err := k.Validate(); err != nil {
		return 0, false
	}
	if len(code) != k.digits() {
		return 0, false
	}
	secret, err := DecodeSecret(k.Secret)
	if err != nil {
		return 0, false
	}
	newH, err := hashFor(k.Algorithm)
	if err != nil {
		return 0, false
	}

	// TOTP drifts in both directions, so its window is symmetric; HOTP only
	// ever looks forward, since re-accepting a counter the server has already
	// passed is precisely the replay it exists to prevent.
	base := k.counterAt(t)
	low, steps := base, window+1
	if k.Type == TOTP {
		if base < uint64(window) {
			low = 0
		} else {
			low = base - uint64(window)
		}
		steps = 2*window + 1
	}

	found := 0
	c := low
	for i := 0; i < steps; i++ {
		candidate := hotp(newH, secret, c, k.digits())
		if subtle.ConstantTimeCompare([]byte(code), []byte(candidate)) == 1 {
			matched = c
			found = 1
		}
		if c == ^uint64(0) { // saturate rather than wrap around
			break
		}
		c++
	}
	return matched, found == 1
}
