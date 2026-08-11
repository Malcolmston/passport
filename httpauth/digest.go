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
	"crypto/subtle"
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

// DigestChallengeParams describes the WWW-Authenticate challenge a server sends
// to start a Digest exchange (RFC 7616 Section 3.3). Only Realm and Nonce are
// required; the remaining fields are omitted from the rendered header when
// empty.
type DigestChallengeParams struct {
	Realm     string // protection space shown in the client's credential prompt
	Nonce     string // server nonce; must be unpredictable and single-use
	Opaque    string // opaque value the client echoes back unchanged
	Algorithm string // AlgMD5, AlgSHA256, AlgSHA512_256, optionally "-sess"
	QOP       string // quality of protection, e.g. "auth" or "auth,auth-int"
	Domain    string // space-separated URIs the credentials are valid for
	Stale     bool   // true when the previous nonce merely expired
	Charset   string // e.g. "UTF-8"
	Userhash  bool   // true when the server accepts a hashed username
}

// DigestChallenge renders p as a WWW-Authenticate header value. All values are
// emitted as quoted-strings via QuoteString except "stale" and "userhash",
// which RFC 7616 defines as unquoted booleans, so a caller-supplied realm or
// nonce cannot inject additional header content.
func DigestChallenge(p DigestChallengeParams) string {
	var b strings.Builder
	b.WriteString(SchemeDigest)
	sep := " "
	add := func(k, v string) {
		if v == "" {
			return
		}
		b.WriteString(sep + k + "=" + QuoteString(v))
		sep = ", "
	}
	// Field order follows passport-http / RFC 7616 Section 3.3
	// (realm, domain, nonce, opaque, algorithm, qop) so the rendered challenge
	// is byte-identical to the upstream oracle's.
	add("realm", p.Realm)
	add("domain", p.Domain)
	add("nonce", p.Nonce)
	add("opaque", p.Opaque)
	add("algorithm", p.Algorithm)
	add("qop", p.QOP)
	add("charset", p.Charset)
	if p.Stale {
		b.WriteString(sep + "stale=true")
		sep = ", "
	}
	if p.Userhash {
		b.WriteString(sep + "userhash=true")
	}
	return b.String()
}

// DigestCredentials is a parsed "Authorization: Digest ..." header.
type DigestCredentials struct {
	Username  string
	Realm     string
	Nonce     string
	URI       string
	Response  string
	Algorithm string
	CNonce    string
	Opaque    string
	QOP       string
	NC        string
	Userhash  bool
	// Params holds every auth-param as parsed, keyed by lower-cased name, so
	// extensions this struct does not model remain reachable.
	Params map[string]string
}

// ParseDigest parses a full "Digest ..." Authorization header value. It returns
// ErrWrongScheme for a header using another scheme, and ErrMalformed when any of
// the parameters RFC 7616 Section 3.4 makes REQUIRED — username, realm, nonce,
// uri, response — is missing or empty.
func ParseDigest(header string) (DigestCredentials, error) {
	scheme, rest, err := ParseScheme(header)
	if err != nil {
		return DigestCredentials{}, err
	}
	if !strings.EqualFold(scheme, SchemeDigest) {
		return DigestCredentials{}, ErrWrongScheme
	}
	p := ParseParams(rest)
	c := DigestCredentials{
		Username:  p["username"],
		Realm:     p["realm"],
		Nonce:     p["nonce"],
		URI:       p["uri"],
		Response:  p["response"],
		Algorithm: p["algorithm"],
		CNonce:    p["cnonce"],
		Opaque:    p["opaque"],
		QOP:       p["qop"],
		NC:        p["nc"],
		Userhash:  strings.EqualFold(p["userhash"], "true"),
		Params:    p,
	}
	// RFC 7616 Section 3.4 makes username, realm, nonce, uri and response all
	// REQUIRED in the credentials. realm in particular is load-bearing: it is
	// hashed into HA1, so a server that accepts a realm-less credential is
	// verifying a digest over a protection space the client never named.
	if c.Username == "" || c.Realm == "" || c.Nonce == "" || c.URI == "" || c.Response == "" {
		return DigestCredentials{}, ErrMalformed
	}
	return c, nil
}

// VerifyDigest recomputes the expected response digest for c using method (the
// HTTP request method), password (the user's cleartext password) and body (only
// consulted when c.QOP is "auth-int"), then compares it against the presented
// c.Response in constant time.
//
// It reports false — rather than an error — for an unsupported algorithm, so a
// caller can treat every rejection identically. The caller remains responsible
// for checking that c.Nonce is one this server issued and has not already seen
// at this nonce-count; without that bookkeeping Digest offers no replay
// protection.
func VerifyDigest(c DigestCredentials, method, password string, body []byte) bool {
	expected, err := DigestResponse(DigestParams{
		Method:    method,
		URI:       c.URI,
		Username:  c.Username,
		Realm:     c.Realm,
		Password:  password,
		Nonce:     c.Nonce,
		NC:        c.NC,
		CNonce:    c.CNonce,
		QOP:       c.QOP,
		Algorithm: c.Algorithm,
		Body:      body,
	})
	if err != nil {
		return false
	}
	// Digest responses are hex, which servers and clients disagree about the
	// case of; compare case-insensitively but still in constant time.
	return subtle.ConstantTimeCompare(
		[]byte(strings.ToLower(expected)),
		[]byte(strings.ToLower(c.Response)),
	) == 1
}
