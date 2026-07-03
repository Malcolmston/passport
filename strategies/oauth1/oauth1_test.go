package oauth1

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/malcolmston/passport"
)

// Twitter's published "Creating a signature" example is a widely used OAuth 1.0a
// (RFC 5849) HMAC-SHA1 test vector with a known signature base string and a
// known resulting signature.
var twitterParams = map[string]string{
	"status":                 "Hello Ladies + Gentlemen, a signed OAuth request!",
	"include_entities":       "true",
	"oauth_consumer_key":     "xvz1evFS4wEEPTGEFPHBog",
	"oauth_nonce":            "kYjzVBB8Y0ZFabxSWbWovY3uYSQ2pTgmZeNu2VS4cg",
	"oauth_signature_method": "HMAC-SHA1",
	"oauth_timestamp":        "1318622958",
	"oauth_token":            "370773112-GmHxMAgYyLbNEtIKZeRNFsMKPR9EyMZeS9weJAEb",
	"oauth_version":          "1.0",
}

const twitterURL = "https://api.twitter.com/1.1/statuses/update.json"

const wantBaseString = "POST&https%3A%2F%2Fapi.twitter.com%2F1.1%2Fstatuses%2Fupdate.json&include_entities%3Dtrue%26oauth_consumer_key%3Dxvz1evFS4wEEPTGEFPHBog%26oauth_nonce%3DkYjzVBB8Y0ZFabxSWbWovY3uYSQ2pTgmZeNu2VS4cg%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D1318622958%26oauth_token%3D370773112-GmHxMAgYyLbNEtIKZeRNFsMKPR9EyMZeS9weJAEb%26oauth_version%3D1.0%26status%3DHello%2520Ladies%2520%252B%2520Gentlemen%252C%2520a%2520signed%2520OAuth%2520request%2521"

func TestSignatureBaseStringVector(t *testing.T) {
	got := signatureBaseString(http.MethodPost, twitterURL, twitterParams)
	if got != wantBaseString {
		t.Fatalf("base string mismatch\n got: %s\nwant: %s", got, wantBaseString)
	}
}

func TestSignVector(t *testing.T) {
	const consumerSecret = "kAcSOqF21Fu85e7zjz7ZN2U4ZRhfV3WpwPAoE3Y7"
	const tokenSecret = "LswwdoUaIVS8ltyTt5jkRh4J50vUPVVHtR2YPi5kE"
	// Independently verified with:
	//   printf '%s' "$BASE" | openssl dgst -sha1 -hmac "$KEY" -binary | openssl base64
	const want = "6NMqKSCvNLGkXsCRrU3yV2AdYfE="

	got := Sign(http.MethodPost, twitterURL, twitterParams, consumerSecret, tokenSecret)
	if got != want {
		t.Fatalf("Sign() = %q, want %q", got, want)
	}
}

func TestPercentEncode(t *testing.T) {
	cases := map[string]string{
		"Ladies + Gentlemen": "Ladies%20%2B%20Gentlemen",
		"An encoded string!": "An%20encoded%20string%21",
		"Dogs, Cats & Mice":  "Dogs%2C%20Cats%20%26%20Mice",
		"~-._":               "~-._",
	}
	for in, want := range cases {
		if got := percentEncode(in); got != want {
			t.Errorf("percentEncode(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestAuthenticateRedirectsAfterRequestToken(t *testing.T) {
	reqTok := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if r.PostForm.Get("oauth_consumer_key") != "ck" {
			t.Errorf("consumer key = %q", r.PostForm.Get("oauth_consumer_key"))
		}
		if r.PostForm.Get("oauth_signature") == "" {
			t.Error("missing oauth_signature")
		}
		_, _ = w.Write([]byte("oauth_token=reqtok&oauth_token_secret=reqsecret&oauth_callback_confirmed=true"))
	}))
	defer reqTok.Close()

	s := New("prov", Config{
		ConsumerKey:     "ck",
		ConsumerSecret:  "cs",
		RequestTokenURL: reqTok.URL,
		AuthorizeURL:    "https://provider.example/authorize",
		HTTPClient:      reqTok.Client(),
	}, func(at, as string, p url.Values) (any, error) { return "u", nil })

	r := httptest.NewRequest(http.MethodGet, "/auth", nil)
	c := &passport.Context{}
	s.Authenticate(c, r)

	if c.Result() != passport.ResultRedirect {
		t.Fatalf("want ResultRedirect, got %v (err=%v)", c.Result(), c.Err())
	}
}

func TestAuthenticateExchangesAccessToken(t *testing.T) {
	accTok := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if r.PostForm.Get("oauth_verifier") != "the-verifier" {
			t.Errorf("verifier = %q", r.PostForm.Get("oauth_verifier"))
		}
		_, _ = w.Write([]byte("oauth_token=acctok&oauth_token_secret=accsecret&screen_name=bob"))
	}))
	defer accTok.Close()

	var gotToken, gotSecret, gotName string
	s := New("prov", Config{
		ConsumerKey:    "ck",
		ConsumerSecret: "cs",
		AccessTokenURL: accTok.URL,
		HTTPClient:     accTok.Client(),
	}, func(at, as string, p url.Values) (any, error) {
		gotToken, gotSecret, gotName = at, as, p.Get("screen_name")
		return map[string]string{"name": gotName}, nil
	})

	r := httptest.NewRequest(http.MethodGet, "/callback?oauth_token=reqtok&oauth_verifier=the-verifier", nil)
	c := &passport.Context{}
	s.Authenticate(c, r)

	if c.Result() != passport.ResultSuccess {
		t.Fatalf("want ResultSuccess, got %v (err=%v)", c.Result(), c.Err())
	}
	if gotToken != "acctok" || gotSecret != "accsecret" || gotName != "bob" {
		t.Errorf("token=%q secret=%q name=%q", gotToken, gotSecret, gotName)
	}
}

func TestName(t *testing.T) {
	s := New("prov", Config{}, nil)
	if s.Name() != "prov" {
		t.Errorf("Name() = %q", s.Name())
	}
}
