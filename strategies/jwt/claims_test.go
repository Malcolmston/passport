package jwt

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/malcolmston/passport"
)

func future() float64 { return float64(time.Now().Add(time.Hour).Unix()) }

// TestIssuerAndAudience covers the passport-jwt issuer/audience options. The
// audience check is what stops a token an issuer minted for one service being
// replayed against another service that trusts the same issuer.
func TestIssuerAndAudience(t *testing.T) {
	key := []byte("k")
	cases := []struct {
		name     string
		claims   Claims
		issuer   string
		audience string
		wantErr  error
	}{
		{"no constraints", Claims{"sub": "u", "exp": future()}, "", "", nil},
		{"issuer matches", Claims{"iss": "idp", "exp": future()}, "idp", "", nil},
		{"issuer differs", Claims{"iss": "evil", "exp": future()}, "idp", "", ErrIssuer},
		{"issuer missing", Claims{"exp": future()}, "idp", "", ErrIssuer},
		{"audience string matches", Claims{"aud": "api", "exp": future()}, "", "api", nil},
		{"audience array contains", Claims{"aud": []any{"web", "api"}, "exp": future()}, "", "api", nil},
		{"audience array excludes", Claims{"aud": []any{"web", "mobile"}, "exp": future()}, "", "api", ErrAudience},
		{"audience differs", Claims{"aud": "other-service", "exp": future()}, "", "api", ErrAudience},
		{"audience missing", Claims{"exp": future()}, "", "api", ErrAudience},
		{"audience wrong type", Claims{"aud": 7, "exp": future()}, "", "api", ErrAudience},
		{"both match", Claims{"iss": "idp", "aud": "api", "exp": future()}, "idp", "api", nil},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			tok, err := Sign(key, tt.claims)
			if err != nil {
				t.Fatal(err)
			}
			s := &Strategy{Secret: key, Issuer: tt.issuer, Audience: tt.audience}
			_, err = s.Parse(tok)
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("Parse error = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

// TestRequireExpiry checks that a token with no exp — which never expires and
// cannot be revoked — is rejected when the option asks for one.
func TestRequireExpiry(t *testing.T) {
	key := []byte("k")
	noExp, err := Sign(key, Claims{"sub": "u"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := (&Strategy{Secret: key}).Parse(noExp); err != nil {
		t.Errorf("without RequireExpiry a token lacking exp is accepted: %v", err)
	}
	if _, err := (&Strategy{Secret: key, RequireExpiry: true}).Parse(noExp); !errors.Is(err, ErrExpired) {
		t.Errorf("with RequireExpiry, error = %v, want ErrExpired", err)
	}
	withExp, err := Sign(key, Claims{"sub": "u", "exp": future()})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := (&Strategy{Secret: key, RequireExpiry: true}).Parse(withExp); err != nil {
		t.Errorf("a token with exp must still pass: %v", err)
	}
}

// TestExtractors exercises each ExtractJwt-equivalent constructor.
func TestExtractors(t *testing.T) {
	const tok = "the.jwt.here"

	bearer := httptest.NewRequest(http.MethodGet, "/", nil)
	bearer.Header.Set("Authorization", "Bearer "+tok)

	scheme := httptest.NewRequest(http.MethodGet, "/", nil)
	scheme.Header.Set("Authorization", "JWT "+tok)

	header := httptest.NewRequest(http.MethodGet, "/", nil)
	header.Header.Set("X-Token", tok)

	query := httptest.NewRequest(http.MethodGet, "/?access_token="+tok, nil)

	body := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("token="+tok))
	body.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	empty := httptest.NewRequest(http.MethodGet, "/", nil)

	cases := []struct {
		name string
		e    Extractor
		r    *http.Request
		want string
	}{
		{"bearer header", FromAuthHeaderAsBearerToken(), bearer, tok},
		{"bearer header case-insensitive", FromAuthHeaderAsBearerToken(), func() *http.Request {
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			r.Header.Set("Authorization", "bEaReR "+tok)
			return r
		}(), tok},
		{"bearer extractor on wrong scheme", FromAuthHeaderAsBearerToken(), scheme, ""},
		{"custom scheme", FromAuthHeaderWithScheme("JWT"), scheme, tok},
		{"named header", FromHeader("X-Token"), header, tok},
		{"query parameter", FromURLQueryParameter("access_token"), query, tok},
		{"body field", FromBodyField("token"), body, tok},
		{"missing everywhere", FromAuthHeaderAsBearerToken(), empty, ""},
		{"chained picks first hit", FromExtractors(nil, FromHeader("X-Nope"), FromHeader("X-Token")), header, tok},
		{"chained with no hit", FromExtractors(FromHeader("X-Nope")), header, ""},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.e(tt.r); got != tt.want {
				t.Errorf("extractor = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestAuthenticateWithCustomExtractor verifies the Extractor field is actually
// consulted by Authenticate, not just available.
func TestAuthenticateWithCustomExtractor(t *testing.T) {
	key := []byte("k")
	tok, err := Sign(key, Claims{"sub": "alice", "exp": future()})
	if err != nil {
		t.Fatal(err)
	}
	s := &Strategy{
		Secret:    key,
		Extractor: FromHeader("X-Access-Token"),
		verify:    func(c Claims) (any, error) { return c.Subject(), nil },
	}

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("X-Access-Token", tok)
	c := &passport.Context{}
	s.Authenticate(c, r)
	if c.Result() != passport.ResultSuccess {
		t.Fatalf("Result() = %v (%v)", c.Result(), c.Err())
	}

	// The same token in the default location must now be ignored.
	r = httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Authorization", "Bearer "+tok)
	c = &passport.Context{}
	s.Authenticate(c, r)
	if c.Result() != passport.ResultFail {
		t.Errorf("Result() = %v, want fail once a custom extractor is set", c.Result())
	}
}

// TestClaimsAudienceNormalization covers both JSON shapes RFC 7519 allows.
func TestClaimsAudienceNormalization(t *testing.T) {
	cases := []struct {
		name   string
		claims Claims
		want   []string
	}{
		{"string", Claims{"aud": "one"}, []string{"one"}},
		{"array", Claims{"aud": []any{"a", "b"}}, []string{"a", "b"}},
		{"array with non-strings", Claims{"aud": []any{"a", 1, true}}, []string{"a"}},
		{"absent", Claims{}, nil},
		{"wrong type", Claims{"aud": 5}, nil},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.claims.Audience()
			if len(got) != len(tt.want) {
				t.Fatalf("Audience() = %v, want %v", got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("Audience()[%d] = %q, want %q", i, got[i], tt.want[i])
				}
			}
		})
	}
	if got := (Claims{"iss": "idp"}).Issuer(); got != "idp" {
		t.Errorf("Issuer() = %q", got)
	}
	if got := (Claims{"iss": 1}).Issuer(); got != "" {
		t.Errorf("Issuer() on a non-string claim = %q, want empty", got)
	}
}
