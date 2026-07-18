package httpauth

import "testing"

func TestEncodeBasicRFC7617(t *testing.T) {
	// RFC 7617 section 2 example: "Aladdin":"open sesame".
	got := EncodeBasic("Aladdin", "open sesame")
	want := "Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ=="
	if got != want {
		t.Errorf("EncodeBasic = %q, want %q", got, want)
	}
}

func TestParseBasic(t *testing.T) {
	c, err := ParseBasic("Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==")
	if err != nil {
		t.Fatal(err)
	}
	if c.Username != "Aladdin" || c.Password != "open sesame" {
		t.Errorf("got %+v", c)
	}
}

func TestParseBasicPasswordWithColon(t *testing.T) {
	h := EncodeBasic("user", "pa:ss:word")
	c, err := ParseBasic(h)
	if err != nil {
		t.Fatal(err)
	}
	if c.Password != "pa:ss:word" {
		t.Errorf("password = %q", c.Password)
	}
}

func TestParseBasicErrors(t *testing.T) {
	if _, err := ParseBasic(""); err != ErrNoHeader {
		t.Errorf("empty err = %v", err)
	}
	if _, err := ParseBasic("Bearer abc"); err != ErrWrongScheme {
		t.Errorf("scheme err = %v", err)
	}
	if _, err := ParseBasic("Basic !!!notbase64"); err != ErrMalformed {
		t.Errorf("b64 err = %v", err)
	}
	// base64 of "nocolon" — valid base64 but no separator.
	if _, err := ParseBasic("Basic bm9jb2xvbg=="); err != ErrMalformed {
		t.Errorf("colon err = %v", err)
	}
}

func TestBearer(t *testing.T) {
	if got := EncodeBearer("abc.def"); got != "Bearer abc.def" {
		t.Errorf("EncodeBearer = %q", got)
	}
	tok, err := ParseBearer("Bearer abc.def")
	if err != nil {
		t.Fatal(err)
	}
	if tok != "abc.def" {
		t.Errorf("token = %q", tok)
	}
	if _, err := ParseBearer("Basic x"); err != ErrWrongScheme {
		t.Errorf("scheme err = %v", err)
	}
}

func TestParseScheme(t *testing.T) {
	s, rest, err := ParseScheme("Digest foo=bar")
	if err != nil || s != "Digest" || rest != "foo=bar" {
		t.Errorf("ParseScheme = %q %q %v", s, rest, err)
	}
	if _, _, err := ParseScheme("Onlyscheme"); err != ErrMalformed {
		t.Errorf("err = %v", err)
	}
}

func TestSchemeHelpers(t *testing.T) {
	if SchemeOf("Bearer abc") != "bearer" {
		t.Errorf("SchemeOf = %q", SchemeOf("Bearer abc"))
	}
	if SchemeOf("") != "" {
		t.Error("SchemeOf empty should be empty")
	}
	if !HasScheme("basic Zm9v", "Basic") {
		t.Error("HasScheme should match case-insensitively")
	}
	if HasScheme("Bearer x", "Basic") {
		t.Error("HasScheme should reject mismatched scheme")
	}
}

func TestChallenges(t *testing.T) {
	if got := BasicChallenge("api"); got != `Basic realm="api"` {
		t.Errorf("BasicChallenge = %q", got)
	}
	if got := BearerChallenge("api", "invalid_token"); got != `Bearer realm="api", error="invalid_token"` {
		t.Errorf("BearerChallenge = %q", got)
	}
	if got := BearerChallenge("", ""); got != "Bearer" {
		t.Errorf("BearerChallenge bare = %q", got)
	}
	if got := BearerChallenge("", "invalid_token"); got != `Bearer error="invalid_token"` {
		t.Errorf("BearerChallenge err only = %q", got)
	}
}
