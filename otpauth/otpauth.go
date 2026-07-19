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
package otpauth

import (
	"crypto/rand"
	"encoding/base32"
	"fmt"
	"net/url"
	"strconv"
	"strings"
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
	} else {
		k.Digits = 6
	}
	if typ == HOTP {
		if c := q.Get("counter"); c != "" {
			if k.Counter, err = strconv.ParseUint(c, 10, 64); err != nil {
				return Key{}, fmt.Errorf("otpauth: invalid counter %q", c)
			}
		}
	} else {
		if p := q.Get("period"); p != "" {
			if k.Period, err = strconv.Atoi(p); err != nil {
				return Key{}, fmt.Errorf("otpauth: invalid period %q", p)
			}
		} else {
			k.Period = 30
		}
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
