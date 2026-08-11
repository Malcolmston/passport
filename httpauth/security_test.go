package httpauth

import (
	"strings"
	"testing"
)

// TestParseSchemeSeparators covers the RFC 7235 rule that one or more spaces or
// tabs may separate the scheme from the credentials, plus the malformed cases.
func TestParseSchemeSeparators(t *testing.T) {
	cases := []struct {
		name       string
		header     string
		wantScheme string
		wantRest   string
		wantErr    error
	}{
		{"single space", "Basic dXNlcjpwdw==", "Basic", "dXNlcjpwdw==", nil},
		{"multiple spaces", "Basic   dXNlcjpwdw==", "Basic", "dXNlcjpwdw==", nil},
		{"tab separator", "Basic\tdXNlcjpwdw==", "Basic", "dXNlcjpwdw==", nil},
		{"leading and trailing space", "  Bearer tok  ", "Bearer", "tok", nil},
		{"empty", "", "", "", ErrNoHeader},
		{"whitespace only", " \t ", "", "", ErrNoHeader},
		{"scheme with no credentials", "Basic", "", "", ErrMalformed},
		{"scheme with empty credentials", "Basic   ", "", "", ErrMalformed},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			scheme, rest, err := ParseScheme(tt.header)
			if err != tt.wantErr {
				t.Fatalf("err = %v, want %v", err, tt.wantErr)
			}
			if scheme != tt.wantScheme || rest != tt.wantRest {
				t.Errorf("got (%q, %q), want (%q, %q)", scheme, rest, tt.wantScheme, tt.wantRest)
			}
		})
	}
}

// TestParseBasicMalformed walks the hostile inputs a public endpoint will
// actually receive. None may panic, and none may yield credentials.
func TestParseBasicMalformed(t *testing.T) {
	for _, header := range []string{
		"",
		"Basic",
		"Basic ",
		"Bearer dXNlcjpwdw==",
		"Basic !!!not-base64!!!",
		"Basic " + strings.Repeat("A", 4001), // valid base64 chars, no colon
		"Basic dXNlcm5hbWU=",                 // decodes to "username", no colon
		"Basic " + "\x00\x01",
	} {
		if creds, err := ParseBasic(header); err == nil {
			t.Errorf("ParseBasic(%q) unexpectedly succeeded with %+v", header, creds)
		}
	}
}

// TestParseBasicAcceptsUnpaddedAndColonPasswords pins two tolerances RFC 7617
// requires or permits: a password may contain colons, and some clients omit
// base64 padding.
func TestParseBasicAcceptsUnpaddedAndColonPasswords(t *testing.T) {
	cases := []struct{ user, pass string }{
		{"alice", "s3cret"},
		{"alice", "pass:with:colons"},
		{"alice", ""},
		{"", "only-password"},
		{"unicode-ü", "påss"},
	}
	for _, tt := range cases {
		got, err := ParseBasic(EncodeBasic(tt.user, tt.pass))
		if err != nil {
			t.Fatalf("round trip of (%q,%q): %v", tt.user, tt.pass, err)
		}
		if got.Username != tt.user || got.Password != tt.pass {
			t.Errorf("round trip = (%q,%q), want (%q,%q)", got.Username, got.Password, tt.user, tt.pass)
		}
	}

	padded := EncodeBasic("alice", "pw")
	unpadded := strings.TrimRight(padded, "=")
	if unpadded == padded {
		t.Skip("this fixture happens not to be padded")
	}
	if _, err := ParseBasic(unpadded); err != nil {
		t.Errorf("unpadded base64 must be accepted: %v", err)
	}
}

// TestMatchesIsConstantTime checks the semantics of the constant-time helper.
// It cannot assert timing, but it can assert that both fields must match.
func TestMatchesIsConstantTime(t *testing.T) {
	c := BasicCredentials{Username: "alice", Password: "s3cret"}
	cases := []struct {
		user, pass string
		want       bool
	}{
		{"alice", "s3cret", true},
		{"alice", "wrong", false},
		{"bob", "s3cret", false},
		{"bob", "wrong", false},
		{"", "", false},
		{"alice", "s3cre", false},
		{"alice", "s3crett", false},
	}
	for _, tt := range cases {
		if got := c.Matches(tt.user, tt.pass); got != tt.want {
			t.Errorf("Matches(%q,%q) = %v, want %v", tt.user, tt.pass, got, tt.want)
		}
	}
	if !SecureCompare("abc", "abc") || SecureCompare("abc", "abd") || SecureCompare("abc", "ab") {
		t.Error("SecureCompare disagrees with plain equality")
	}
}

// TestChallengeQuotingBlocksHeaderInjection pins the response-splitting guard:
// nothing a realm contains may terminate the header value or start a new one.
func TestChallengeQuotingBlocksHeaderInjection(t *testing.T) {
	hostile := "evil\"\r\nX-Injected: yes\r\n"
	for name, got := range map[string]string{
		"basic":  BasicChallenge(hostile),
		"bearer": BearerChallenge(hostile, "invalid_token"),
		"digest": DigestChallenge(DigestChallengeParams{Realm: hostile, Nonce: "abc", QOP: "auth"}),
	} {
		if strings.ContainsAny(got, "\r\n") {
			t.Errorf("%s challenge %q still contains a line break", name, got)
		}
		if strings.Contains(got, "X-Injected: yes\r\n") {
			t.Errorf("%s challenge allowed header injection: %q", name, got)
		}
		if !strings.Contains(got, `\"`) {
			t.Errorf("%s challenge did not escape the embedded quote: %q", name, got)
		}
	}

	if got := BasicChallenge("Users"); got != `Basic realm="Users"` {
		t.Errorf("ordinary realm = %q", got)
	}
	if got := BearerChallenge("", "invalid_token"); got != `Bearer error="invalid_token"` {
		t.Errorf("realm-less bearer challenge = %q", got)
	}
	if got := QuoteString(`a\b"c`); got != `"a\\b\"c"` {
		t.Errorf("QuoteString = %q", got)
	}
}

// TestParseDigestAndVerify round-trips a Digest credential through the
// challenge, response computation, parser, and verifier.
func TestParseDigestAndVerify(t *testing.T) {
	const (
		user   = "Mufasa"
		realm  = "http-auth@example.org"
		pass   = "Circle of Life"
		nonce  = "7ypf/xlj9XXwfDPEoM4URrv/xwf94BcCAzFZH4GiTo0v"
		cnonce = "f2/wE4q74E6zIJEtWaHKaf5wv/H5QzzpXusqGemxURZJ"
		uri    = "/dir/index.html"
	)
	resp, err := DigestResponse(DigestParams{
		Method: "GET", URI: uri, Username: user, Realm: realm, Password: pass,
		Nonce: nonce, NC: "00000001", CNonce: cnonce, QOP: "auth", Algorithm: AlgMD5,
	})
	if err != nil {
		t.Fatal(err)
	}

	header := `Digest username="` + user + `", realm="` + realm + `", uri="` + uri +
		`", algorithm=MD5, nonce="` + nonce + `", nc=00000001, cnonce="` + cnonce +
		`", qop=auth, response="` + resp + `", opaque="op4que"`

	creds, err := ParseDigest(header)
	if err != nil {
		t.Fatalf("ParseDigest: %v", err)
	}
	if creds.Username != user || creds.Realm != realm || creds.URI != uri ||
		creds.NC != "00000001" || creds.CNonce != cnonce || creds.QOP != "auth" ||
		creds.Opaque != "op4que" || creds.Algorithm != "MD5" {
		t.Errorf("parsed credentials are wrong: %+v", creds)
	}
	if !VerifyDigest(creds, "GET", pass, nil) {
		t.Error("VerifyDigest rejected a correctly computed response")
	}
	if VerifyDigest(creds, "GET", "wrong password", nil) {
		t.Error("VerifyDigest accepted a wrong password")
	}
	if VerifyDigest(creds, "POST", pass, nil) {
		t.Error("VerifyDigest ignored the request method")
	}

	// Hex case must not matter.
	creds.Response = strings.ToUpper(creds.Response)
	if !VerifyDigest(creds, "GET", pass, nil) {
		t.Error("VerifyDigest is sensitive to the case of the hex response")
	}

	// An unsupported algorithm must fail closed, not panic.
	creds.Algorithm = "SHA-3"
	if VerifyDigest(creds, "GET", pass, nil) {
		t.Error("VerifyDigest accepted an unsupported algorithm")
	}
}

// TestParseDigestRejectsIncomplete covers headers missing a mandatory field.
func TestParseDigestRejectsIncomplete(t *testing.T) {
	for _, header := range []string{
		"",
		"Digest",
		"Basic dXNlcjpwdw==",
		`Digest realm="r"`,
		`Digest username="u"`,
		`Digest username="u", nonce="n"`,
		`Digest username="u", nonce="n", uri="/"`,
	} {
		if creds, err := ParseDigest(header); err == nil {
			t.Errorf("ParseDigest(%q) unexpectedly succeeded with %+v", header, creds)
		}
	}
}

// TestParseParamsQuoting checks the auth-param parser against values that
// contain the delimiters it splits on.
func TestParseParamsQuoting(t *testing.T) {
	got := ParseParams(`realm="a, b", NONCE="x\"y", nc=00000001, empty="", bare`)
	want := map[string]string{
		"realm": "a, b",
		"nonce": `x"y`,
		"nc":    "00000001",
		"empty": "",
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("param %q = %q, want %q", k, got[k], v)
		}
	}
	if _, ok := got["bare"]; ok {
		t.Error("a field with no '=' must be skipped")
	}
}
