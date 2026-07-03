package hotp

import (
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/malcolmston/passport"
)

// RFC 4226 Appendix D test vectors for the secret "12345678901234567890".
var rfcVectors = []string{
	"755224", "287082", "359152", "969429", "338314",
	"254676", "287922", "162583", "399871", "520489",
}

func TestGenerateRFC4226(t *testing.T) {
	secret := []byte("12345678901234567890")
	for i, want := range rfcVectors {
		if got := Generate(secret, uint64(i)); got != want {
			t.Errorf("counter %d: got %s want %s", i, got, want)
		}
	}
}

func opts() Options {
	return Options{
		Secret:  func(u string) ([]byte, error) { return []byte("12345678901234567890"), nil },
		Counter: func(u string) (uint64, error) { return 0, nil },
	}
}

func post(user, code string) *passport.Context {
	form := url.Values{"user": {user}, "code": {code}}
	r := httptest.NewRequest("POST", "/", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	c := &passport.Context{}
	New(opts()).Authenticate(c, r)
	return c
}

func TestValidCode(t *testing.T) {
	c := post("alice", "755224")
	if c.Result() != passport.ResultSuccess || c.SuccessUser() != "alice" {
		t.Fatalf("result=%v user=%v", c.Result(), c.SuccessUser())
	}
}

func TestLookAhead(t *testing.T) {
	// Counter is 0 on the server but client is at counter 2 (window=3).
	c := post("alice", "359152")
	if c.Result() != passport.ResultSuccess {
		t.Fatalf("result=%v", c.Result())
	}
}

func TestOutsideWindow(t *testing.T) {
	// Counter 5 is beyond the default window of 3.
	c := post("alice", "254676")
	if c.Result() != passport.ResultFail {
		t.Fatalf("result=%v", c.Result())
	}
}

func TestMissing(t *testing.T) {
	c := post("", "")
	if c.Result() != passport.ResultFail {
		t.Fatalf("result=%v", c.Result())
	}
}

func TestName(t *testing.T) {
	if New(opts()).Name() != "hotp" {
		t.Fatal("name")
	}
}
