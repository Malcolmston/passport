// This file adds HTTP Digest Access Authentication (RFC 7616) to the httpauth
// package. The response-digest computation follows RFC 7616 Section 3.4.6
// exactly and is verified against the canonical worked example in RFC 7616
// Section 3.9.1 (see httpauth_parity_test.go). Only the standard library is
// used; the crypto/* hashes are the ones the specification names.
package httpauth

import (
	"crypto/md5"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"hash"
	"strings"
)

// SchemeDigest names the HTTP Digest authentication scheme (RFC 7616).
const SchemeDigest = "Digest"

// Digest algorithm names defined by RFC 7616 Section 3.3. Each may also appear
// with a "-sess" suffix (session variant, RFC 7616 Section 3.4.2).
const (
	AlgMD5        = "MD5"
	AlgSHA256     = "SHA-256"
	AlgSHA512_256 = "SHA-512-256"
)

// ErrUnknownAlgorithm indicates a Digest "algorithm" value this package does
// not implement.
var ErrUnknownAlgorithm = errors.New("httpauth: unknown digest algorithm")

// DigestParams holds the inputs to an RFC 7616 digest-response computation. The
// same struct drives both the client (build an Authorization response) and the
// server (recompute and compare).
type DigestParams struct {
	Method   string // HTTP method, e.g. "GET".
	URI      string // Request-target as sent in the "uri" digest field.
	Username string
	Realm    string
	Password string
	Nonce    string // Server-provided nonce.
	NC       string // nonce-count, 8 lowercase hex digits, e.g. "00000001".
	CNonce   string // Client-provided nonce.
	QOP      string // "auth", "auth-int", or "" for the legacy RFC 2069 form.
	// Algorithm is one of AlgMD5, AlgSHA256, AlgSHA512_256, optionally with a
	// "-sess" suffix. An empty value defaults to MD5 per RFC 7616 Section 3.4.
	Algorithm string
	// Body is the entity body, hashed only when QOP is "auth-int"
	// (RFC 7616 Section 3.4.3). It is ignored otherwise.
	Body []byte
}

// newHash returns a fresh hash for the named digest algorithm and reports
// whether the name carried the "-sess" suffix. An empty name means MD5.
func newHash(algorithm string) (func() hash.Hash, bool, error) {
	name := strings.TrimSpace(algorithm)
	sess := false
	if u := strings.ToUpper(name); strings.HasSuffix(u, "-SESS") {
		sess = true
		name = name[:len(name)-len("-sess")]
	}
	switch strings.ToUpper(name) {
	case "", AlgMD5:
		return md5.New, sess, nil
	case AlgSHA256:
		return sha256.New, sess, nil
	case AlgSHA512_256:
		return sha512.New512_256, sess, nil
	default:
		return nil, false, ErrUnknownAlgorithm
	}
}

// DigestResponse computes the hex "response" value for a Digest credential per
// RFC 7616 Section 3.4.6. It returns ErrUnknownAlgorithm for an algorithm this
// package does not support.
func DigestResponse(p DigestParams) (string, error) {
	newH, sess, err := newHash(p.Algorithm)
	if err != nil {
		return "", err
	}
	h := func(s string) string {
		hh := newH()
		hh.Write([]byte(s))
		return hex.EncodeToString(hh.Sum(nil))
	}

	// A1 and H(A1). RFC 7616 Section 3.4.2.
	a1 := p.Username + ":" + p.Realm + ":" + p.Password
	ha1 := h(a1)
	if sess {
		ha1 = h(ha1 + ":" + p.Nonce + ":" + p.CNonce)
	}

	// A2 and H(A2). RFC 7616 Section 3.4.3.
	a2 := p.Method + ":" + p.URI
	if strings.EqualFold(p.QOP, "auth-int") {
		hb := newH()
		hb.Write(p.Body)
		a2 += ":" + hex.EncodeToString(hb.Sum(nil))
	}
	ha2 := h(a2)

	// Response. RFC 7616 Section 3.4.6; the qop-less branch is the RFC 2069
	// backward-compatible form.
	if p.QOP == "" {
		return h(ha1 + ":" + p.Nonce + ":" + ha2), nil
	}
	return h(ha1 + ":" + p.Nonce + ":" + p.NC + ":" + p.CNonce + ":" + p.QOP + ":" + ha2), nil
}

// ParseParams parses the comma-separated auth-param list that follows the scheme
// token in a WWW-Authenticate or Authorization header (e.g. the part after
// "Digest "). Keys are lower-cased; quoted-string values are unquoted and their
// backslash escapes removed. It is tolerant of surrounding whitespace.
func ParseParams(rest string) map[string]string {
	params := make(map[string]string)
	for _, field := range splitParams(rest) {
		field = strings.TrimSpace(field)
		if field == "" {
			continue
		}
		eq := strings.IndexByte(field, '=')
		if eq < 0 {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(field[:eq]))
		val := strings.TrimSpace(field[eq+1:])
		if len(val) >= 2 && val[0] == '"' && val[len(val)-1] == '"' {
			val = unquote(val[1 : len(val)-1])
		}
		if key != "" {
			params[key] = val
		}
	}
	return params
}

// splitParams splits on commas that are not inside a quoted string.
func splitParams(s string) []string {
	var out []string
	var buf strings.Builder
	inQuote := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '\\' && inQuote && i+1 < len(s):
			buf.WriteByte(c)
			i++
			buf.WriteByte(s[i])
		case c == '"':
			inQuote = !inQuote
			buf.WriteByte(c)
		case c == ',' && !inQuote:
			out = append(out, buf.String())
			buf.Reset()
		default:
			buf.WriteByte(c)
		}
	}
	if buf.Len() > 0 {
		out = append(out, buf.String())
	}
	return out
}

// unquote removes backslash escapes from a quoted-string body.
func unquote(s string) string {
	if !strings.ContainsRune(s, '\\') {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+1 < len(s) {
			i++
		}
		b.WriteByte(s[i])
	}
	return b.String()
}
