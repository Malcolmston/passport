package httpauth

// Deep spec-parity tests. Each block encodes canonical test vectors taken
// verbatim from the authoritative specification (or, for the classic MD5
// known-answer, RFC 2617), and cites the exact source. Run with:
//
//	go test ./httpauth/... -run Parity
//
// Vector sources (rfc-editor.org is egress-blocked in this environment; the
// famous fixed values were cross-checked against multiple reference
// implementations via raw.githubusercontent.com / GitHub code search, e.g.
// chromium/chromium net/http/http_auth_handler_digest_unittest.cc):
//   - RFC 7617  "The 'Basic' HTTP Authentication Scheme", Sections 2 and 2.1
//   - RFC 7616  "HTTP Digest Access Authentication", Sections 3.4 and 3.9.1
//   - RFC 2617  "HTTP Authentication: Basic and Digest ...", Section 3.5

import "testing"

// TestParityBasicRFC7617 covers the RFC 7617 Basic vectors.
func TestParityBasicRFC7617(t *testing.T) {
	// RFC 7617 Section 2: user-id "Aladdin", password "open sesame".
	//   base64("Aladdin:open sesame") = "QWxhZGRpbjpvcGVuIHNlc2FtZQ=="
	if got := EncodeBasic("Aladdin", "open sesame"); got != "Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==" {
		t.Errorf("Aladdin encode = %q", got)
	}
	if c, err := ParseBasic("Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ=="); err != nil ||
		c.Username != "Aladdin" || c.Password != "open sesame" {
		t.Errorf("Aladdin parse = %+v err=%v", c, err)
	}

	// Common "test:test" vector -> base64 "dGVzdDp0ZXN0".
	if got := EncodeBasic("test", "test"); got != "Basic dGVzdDp0ZXN0" {
		t.Errorf("test:test encode = %q", got)
	}
	if c, err := ParseBasic("Basic dGVzdDp0ZXN0"); err != nil ||
		c.Username != "test" || c.Password != "test" {
		t.Errorf("test:test parse = %+v err=%v", c, err)
	}

	// RFC 7617 Section 2.1 (charset "UTF-8"): user-id "test", password
	// "123" followed by U+00A3 POUND SIGN (£). The user-pass octets are
	// 74 65 73 74 3A 31 32 33 C2 A3, whose base64 is "dGVzdDoxMjPCow==".
	utf8Pass := "123£"
	if got := EncodeBasic("test", utf8Pass); got != "Basic dGVzdDoxMjPCow==" {
		t.Errorf("UTF-8 encode = %q", got)
	}
	if c, err := ParseBasic("Basic dGVzdDoxMjPCow=="); err != nil ||
		c.Username != "test" || c.Password != utf8Pass {
		t.Errorf("UTF-8 parse = %+v err=%v", c, err)
	}
}

// TestParityBasicChallengeRFC7617 covers the WWW-Authenticate challenge form.
func TestParityBasicChallengeRFC7617(t *testing.T) {
	// RFC 7617 Section 2 example challenge uses realm "WallyWorld":
	//   WWW-Authenticate: Basic realm="WallyWorld"
	if got := BasicChallenge("WallyWorld"); got != `Basic realm="WallyWorld"` {
		t.Errorf("BasicChallenge = %q", got)
	}
}

// TestParityDigestSHA256RFC7616 is the canonical RFC 7616 Section 3.9.1
// worked example (SHA-256).
func TestParityDigestSHA256RFC7616(t *testing.T) {
	p := DigestParams{
		Method:    "GET",
		URI:       "/dir/index.html",
		Username:  "Mufasa",
		Realm:     "http-auth@example.org",
		Password:  "Circle of Life",
		Nonce:     "7ypf/xlj9XXwfDPEoM4URrv/xwf94BcCAzFZH4GiTo0v",
		NC:        "00000001",
		CNonce:    "f2/wE4q74E6zIJEtWaHKaf5wv/H5QzzpXusqGemxURZJ",
		QOP:       "auth",
		Algorithm: AlgSHA256,
	}
	const want = "753927fa0e85d155564e2e272a28d1802ca10daf4496794697cf8db5856cb6c1"
	got, err := DigestResponse(p)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Errorf("SHA-256 response = %q, want %q", got, want)
	}
}

// TestParityDigestMD5RFC2617 is the classic RFC 2617 Section 3.5 MD5
// known-answer (the reference MD5 digest vector, carried forward by RFC 7616's
// backward compatibility). It exercises the MD5 branch of DigestResponse.
func TestParityDigestMD5RFC2617(t *testing.T) {
	p := DigestParams{
		Method:    "GET",
		URI:       "/dir/index.html",
		Username:  "Mufasa",
		Realm:     "testrealm@host.com",
		Password:  "Circle Of Life",
		Nonce:     "dcd98b7102dd2f0e8b11d0f600bfb0c093",
		NC:        "00000001",
		CNonce:    "0a4f113b",
		QOP:       "auth",
		Algorithm: AlgMD5,
	}
	const want = "6629fae49393a05397450978507c4ef1"
	got, err := DigestResponse(p)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Errorf("MD5 response = %q, want %q", got, want)
	}

	// Empty Algorithm must default to MD5 (RFC 7616 Section 3.4).
	p.Algorithm = ""
	if got, err := DigestResponse(p); err != nil || got != want {
		t.Errorf("default-algorithm response = %q err=%v, want %q", got, err, want)
	}
}

// TestParityDigestParseAndVerifyRFC7616 parses the Authorization header from the
// RFC 7616 Section 3.9.1 example and recomputes the response, confirming the
// parse -> verify round trip against the printed digest.
func TestParityDigestParseAndVerifyRFC7616(t *testing.T) {
	// Authorization header as shown in RFC 7616 Section 3.9.1.
	const header = `Digest username="Mufasa", ` +
		`realm="http-auth@example.org", ` +
		`uri="/dir/index.html", ` +
		`algorithm=SHA-256, ` +
		`nonce="7ypf/xlj9XXwfDPEoM4URrv/xwf94BcCAzFZH4GiTo0v", ` +
		`nc=00000001, ` +
		`cnonce="f2/wE4q74E6zIJEtWaHKaf5wv/H5QzzpXusqGemxURZJ", ` +
		`qop=auth, ` +
		`response="753927fa0e85d155564e2e272a28d1802ca10daf4496794697cf8db5856cb6c1", ` +
		`opaque="FQhe/qaU925kfnzjCev0ciny7QMkPqMAFRtzCUYo5tdS"`

	scheme, rest, err := ParseScheme(header)
	if err != nil || scheme != SchemeDigest {
		t.Fatalf("ParseScheme = %q rest=%q err=%v", scheme, rest, err)
	}
	fields := ParseParams(rest)

	// Spot-check unquoting of representative fields.
	if fields["username"] != "Mufasa" {
		t.Errorf("username = %q", fields["username"])
	}
	if fields["realm"] != "http-auth@example.org" {
		t.Errorf("realm = %q", fields["realm"])
	}
	if fields["algorithm"] != "SHA-256" {
		t.Errorf("algorithm = %q", fields["algorithm"])
	}
	if fields["qop"] != "auth" {
		t.Errorf("qop = %q", fields["qop"])
	}
	if fields["nc"] != "00000001" {
		t.Errorf("nc = %q", fields["nc"])
	}
	if fields["opaque"] != "FQhe/qaU925kfnzjCev0ciny7QMkPqMAFRtzCUYo5tdS" {
		t.Errorf("opaque = %q", fields["opaque"])
	}

	// Server side: recompute the response from the parsed fields and the
	// shared secret, then compare to the client-sent response.
	got, err := DigestResponse(DigestParams{
		Method:    "GET",
		URI:       fields["uri"],
		Username:  fields["username"],
		Realm:     fields["realm"],
		Password:  "Circle of Life",
		Nonce:     fields["nonce"],
		NC:        fields["nc"],
		CNonce:    fields["cnonce"],
		QOP:       fields["qop"],
		Algorithm: fields["algorithm"],
	})
	if err != nil {
		t.Fatal(err)
	}
	if got != fields["response"] {
		t.Errorf("recomputed response = %q, want %q", got, fields["response"])
	}
}

// TestParityDigestUnknownAlgorithm confirms unsupported algorithms are rejected
// rather than silently mishandled.
func TestParityDigestUnknownAlgorithm(t *testing.T) {
	if _, err := DigestResponse(DigestParams{Algorithm: "SHA-1"}); err != ErrUnknownAlgorithm {
		t.Errorf("err = %v, want ErrUnknownAlgorithm", err)
	}
}
