package digest

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/malcolmston/passport"
)

const (
	realm  = "testrealm@host.com"
	user   = "Mufasa"
	pass   = "Circle Of Life"
	nonce  = "dcd98b7102dd2f0e8b11d0f600bfb0c093"
	cnonce = "0a4f113b"
	nc     = "00000001"
)

func secret(u string) string {
	if u == user {
		return pass
	}
	return ""
}

// buildAuth constructs a valid Digest Authorization header for GET uri.
func buildAuth(uri string) string {
	ha1 := md5hex(user + ":" + realm + ":" + pass)
	ha2 := md5hex("GET:" + uri)
	response := md5hex(strings.Join([]string{ha1, nonce, nc, cnonce, "auth", ha2}, ":"))
	return "Digest username=\"" + user + "\", realm=\"" + realm + "\", nonce=\"" + nonce +
		"\", uri=\"" + uri + "\", qop=auth, nc=" + nc + ", cnonce=\"" + cnonce +
		"\", response=\"" + response + "\""
}

func newStrategy() *Strategy {
	return New(Options{Realm: realm, Secret: secret, Nonce: func() string { return nonce }})
}

func TestChallengeWhenAbsent(t *testing.T) {
	w := httptest.NewRecorder()
	s := newStrategy()
	c := &passport.Context{Writer: w}
	s.Authenticate(c, httptest.NewRequest("GET", "/dir/index.html", nil))
	if c.Result() != passport.ResultFail {
		t.Fatalf("result=%v", c.Result())
	}
	wa := w.Header().Get("WWW-Authenticate")
	if !strings.Contains(wa, "nonce=\""+nonce+"\"") || !strings.Contains(wa, "qop=\"auth\"") {
		t.Fatalf("challenge=%q", wa)
	}
}

func TestValidResponse(t *testing.T) {
	uri := "/dir/index.html"
	r := httptest.NewRequest("GET", uri, nil)
	r.Header.Set("Authorization", buildAuth(uri))
	c := &passport.Context{}
	newStrategy().Authenticate(c, r)
	if c.Result() != passport.ResultSuccess || c.SuccessUser() != user {
		t.Fatalf("result=%v user=%v", c.Result(), c.SuccessUser())
	}
}

func TestWrongResponse(t *testing.T) {
	uri := "/dir/index.html"
	r := httptest.NewRequest("GET", uri, nil)
	auth := buildAuth(uri)
	auth = strings.Replace(auth, "response=\"", "response=\"ffff", 1)
	r.Header.Set("Authorization", auth)
	c := &passport.Context{}
	newStrategy().Authenticate(c, r)
	if c.Result() != passport.ResultFail {
		t.Fatalf("result=%v", c.Result())
	}
}

func TestUnknownUser(t *testing.T) {
	uri := "/x"
	// Build for a user the secret func rejects.
	ha1 := md5hex("ghost:" + realm + ":pw")
	ha2 := md5hex("GET:" + uri)
	resp := md5hex(strings.Join([]string{ha1, nonce, nc, cnonce, "auth", ha2}, ":"))
	auth := "Digest username=\"ghost\", realm=\"" + realm + "\", nonce=\"" + nonce +
		"\", uri=\"" + uri + "\", qop=auth, nc=" + nc + ", cnonce=\"" + cnonce +
		"\", response=\"" + resp + "\""
	r := httptest.NewRequest("GET", uri, nil)
	r.Header.Set("Authorization", auth)
	c := &passport.Context{}
	newStrategy().Authenticate(c, r)
	if c.Result() != passport.ResultFail {
		t.Fatalf("result=%v", c.Result())
	}
}

func TestName(t *testing.T) {
	if newStrategy().Name() != "digest" {
		t.Fatal("name")
	}
}
