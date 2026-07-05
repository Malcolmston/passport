// Package oauth1 implements the core of an OAuth 1.0a (RFC 5849) authentication
// strategy using HMAC-SHA1 signatures, built on the standard library only. It
// is the shared base that provider wrappers such as strategies/oauth1twitter
// build on: those packages preset the request-token, authorize, and
// access-token endpoints and delegate the entire signing and HTTP dance to this
// package. It ports passport-oauth1, the Node base strategy behind the
// OAuth 1.0a provider strategies (Twitter and friends), and so it is the core
// abstraction rather than a standalone provider.
//
// Use this package directly when you must authenticate against an OAuth 1.0a
// provider that has no dedicated wrapper — anything still speaking the pre-OAuth2
// three-legged protocol with HMAC-SHA1 request signing. Supply the three
// provider endpoints and your consumer key/secret in a Config and you get a
// ready passport.Strategy. When a wrapper exists (oauth1twitter), prefer it: it
// returns a *Strategy from this package, so everything documented here applies.
//
// The strategy drives the three-legged flow. On a request with no oauth_verifier
// it performs the first leg: it obtains a temporary request token from
// RequestTokenURL (sending oauth_callback when CallbackURL is set) and redirects
// the user agent to AuthorizeURL with that oauth_token. The provider
// authenticates the user and redirects back to the callback with an
// oauth_verifier; on that second request the strategy performs the final leg,
// exchanging the (oauth_token, oauth_verifier) pair at AccessTokenURL for a
// long-lived access token and secret, which it passes to the VerifyFunc.
//
// Two pieces of machinery are exported for direct use and testing. Sign computes
// the OAuth 1.0a HMAC-SHA1 oauth_signature for a request; its signature base
// string construction follows RFC 5849 section 3.4.1 exactly (uppercase method,
// percent-encoded base URI, sorted percent-encoded parameter string) and is
// verified against a published test vector. The signing key is
// percentEncode(consumerSecret) + "&" + percentEncode(tokenSecret), so the empty
// token secret used before an access token exists still produces a valid key.
//
// SIMPLIFIED, and the one deviation from a production flow: this implementation
// signs the access-token exchange with an empty token secret. A complete
// three-legged flow must persist the request-token secret returned by the
// request-token step in the user's session and use it as the token secret when
// signing the access-token request. That cross-redirect session plumbing is
// intentionally out of scope; the signing core and HTTP flow here are complete
// and correct. As with every strategy in this port, the VerifyFunc returns a
// non-nil user to log in, a nil user (with nil error) to reject as an HTTP 401
// failure, and a non-nil error to signal an internal error.
package oauth1

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"

	"github.com/malcolmston/passport"
)

// Config holds the client credentials and endpoints for an OAuth 1.0a provider.
type Config struct {
	ConsumerKey    string // OAuth 1.0a consumer (application) key
	ConsumerSecret string // OAuth 1.0a consumer (application) secret

	RequestTokenURL string // provider endpoint that issues request tokens
	AuthorizeURL    string // provider endpoint the user is redirected to
	AccessTokenURL  string // provider endpoint that exchanges for access tokens
	CallbackURL     string // URL the provider redirects back to after authorization

	// HTTPClient is used for the request-token and access-token exchanges.
	// When nil, http.DefaultClient is used. Injectable for tests.
	HTTPClient *http.Client
}

// VerifyFunc maps a granted access token (and the raw token-endpoint response
// parameters) to an application user. Returning a nil user (with nil error) is
// treated as an authentication failure.
type VerifyFunc func(accessToken, accessSecret string, params url.Values) (user any, err error)

// Strategy is a generic OAuth 1.0a (HMAC-SHA1) authorization strategy.
type Strategy struct {
	name   string
	cfg    Config
	verify VerifyFunc

	// nonceFn and timeFn are injectable so tests can be deterministic.
	nonceFn func() string
	timeFn  func() time.Time
}

// New creates a Strategy registered under name.
func New(name string, cfg Config, verify VerifyFunc) *Strategy {
	return &Strategy{
		name:    name,
		cfg:     cfg,
		verify:  verify,
		nonceFn: defaultNonce,
		timeFn:  time.Now,
	}
}

// Name returns the strategy name.
func (s *Strategy) Name() string { return s.name }

func (s *Strategy) httpClient() *http.Client {
	if s.cfg.HTTPClient != nil {
		return s.cfg.HTTPClient
	}
	return http.DefaultClient
}

// Authenticate implements passport.Strategy. With no oauth_verifier in the
// query it fetches a request token and redirects to the authorize endpoint;
// with an oauth_verifier it exchanges for an access token and runs verify.
func (s *Strategy) Authenticate(c *passport.Context, r *http.Request) {
	q := r.URL.Query()
	verifier := q.Get("oauth_verifier")

	if verifier == "" {
		// First leg: obtain a request token, then redirect to authorize.
		token, _, err := s.getRequestToken()
		if err != nil {
			c.Error(err)
			return
		}
		sep := "?"
		if strings.Contains(s.cfg.AuthorizeURL, "?") {
			sep = "&"
		}
		loc := s.cfg.AuthorizeURL + sep + "oauth_token=" + percentEncode(token)
		c.Redirect(loc, http.StatusFound)
		return
	}

	// Callback leg: exchange the (token, verifier) for an access token.
	token := q.Get("oauth_token")
	accessToken, accessSecret, params, err := s.getAccessToken(token, verifier)
	if err != nil {
		c.Error(err)
		return
	}
	user, err := s.verify(accessToken, accessSecret, params)
	if err != nil {
		c.Error(err)
		return
	}
	if user == nil {
		c.Fail("", http.StatusUnauthorized)
		return
	}
	c.Success(user)
}

// getRequestToken performs the request-token step and returns the request token
// and its secret.
func (s *Strategy) getRequestToken() (token, secret string, err error) {
	extra := map[string]string{}
	if s.cfg.CallbackURL != "" {
		extra["oauth_callback"] = s.cfg.CallbackURL
	}
	vals, err := s.post(s.cfg.RequestTokenURL, extra, "")
	if err != nil {
		return "", "", err
	}
	return vals.Get("oauth_token"), vals.Get("oauth_token_secret"), nil
}

// getAccessToken performs the access-token step.
func (s *Strategy) getAccessToken(token, verifier string) (accessToken, accessSecret string, params url.Values, err error) {
	extra := map[string]string{
		"oauth_token":    token,
		"oauth_verifier": verifier,
	}
	// SIMPLIFIED: the request token secret is not carried across the redirect,
	// so we sign with an empty token secret. See the package doc comment.
	vals, err := s.post(s.cfg.AccessTokenURL, extra, "")
	if err != nil {
		return "", "", nil, err
	}
	return vals.Get("oauth_token"), vals.Get("oauth_token_secret"), vals, nil
}

// post signs and POSTs an OAuth 1.0a request, sending the OAuth protocol
// parameters as the form body, and parses the form-encoded response.
func (s *Strategy) post(endpoint string, extra map[string]string, tokenSecret string) (url.Values, error) {
	params := s.oauthParams()
	for k, v := range extra {
		params[k] = v
	}
	params["oauth_signature"] = Sign(http.MethodPost, endpoint, params, s.cfg.ConsumerSecret, tokenSecret)

	form := url.Values{}
	for k, v := range params {
		form.Set(k, v)
	}
	req, err := http.NewRequest(http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := s.httpClient().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("oauth1: endpoint %s returned %d: %s", endpoint, resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return url.ParseQuery(string(body))
}

// oauthParams returns the standard OAuth protocol parameters (without a
// signature) for a new request.
func (s *Strategy) oauthParams() map[string]string {
	return map[string]string{
		"oauth_consumer_key":     s.cfg.ConsumerKey,
		"oauth_nonce":            s.nonceFn(),
		"oauth_signature_method": "HMAC-SHA1",
		"oauth_timestamp":        strconv.FormatInt(s.timeFn().Unix(), 10),
		"oauth_version":          "1.0",
	}
}

// Sign computes the OAuth 1.0a HMAC-SHA1 oauth_signature (base64-encoded) for a
// request. params must contain every protocol and request parameter except
// oauth_signature itself. The signing key is
// percentEncode(consumerSecret) + "&" + percentEncode(tokenSecret).
func Sign(method, rawURL string, params map[string]string, consumerSecret, tokenSecret string) string {
	base := signatureBaseString(method, rawURL, params)
	key := percentEncode(consumerSecret) + "&" + percentEncode(tokenSecret)
	mac := hmac.New(sha1.New, []byte(key))
	mac.Write([]byte(base))
	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

// signatureBaseString builds the RFC 5849 section 3.4.1.1 signature base string:
// METHOD & percentEncode(base URL) & percentEncode(normalized parameter string).
func signatureBaseString(method, rawURL string, params map[string]string) string {
	// Normalized parameters: percent-encode each key and value, sort by the
	// encoded key (then encoded value), and join as k=v pairs with '&'.
	type kv struct{ k, v string }
	pairs := make([]kv, 0, len(params))
	for k, v := range params {
		if k == "oauth_signature" {
			continue
		}
		pairs = append(pairs, kv{percentEncode(k), percentEncode(v)})
	}
	sort.Slice(pairs, func(i, j int) bool {
		if pairs[i].k == pairs[j].k {
			return pairs[i].v < pairs[j].v
		}
		return pairs[i].k < pairs[j].k
	})
	parts := make([]string, len(pairs))
	for i, p := range pairs {
		parts[i] = p.k + "=" + p.v
	}
	paramString := strings.Join(parts, "&")

	return strings.ToUpper(method) + "&" + percentEncode(baseStringURI(rawURL)) + "&" + percentEncode(paramString)
}

// baseStringURI normalizes a request URL for use in the signature base string:
// lowercase scheme and host, default ports removed, no query or fragment.
func baseStringURI(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	scheme := strings.ToLower(u.Scheme)
	host := strings.ToLower(u.Host)
	// Strip default ports.
	if (scheme == "http" && strings.HasSuffix(host, ":80")) ||
		(scheme == "https" && strings.HasSuffix(host, ":443")) {
		host = host[:strings.LastIndex(host, ":")]
	}
	return scheme + "://" + host + u.EscapedPath()
}

// percentEncode implements RFC 3986 / RFC 5849 percent-encoding: every byte
// except the unreserved set (A-Z a-z 0-9 - . _ ~) is encoded as %XX (uppercase).
func percentEncode(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
			c == '-' || c == '.' || c == '_' || c == '~' {
			b.WriteByte(c)
		} else {
			b.WriteString(fmt.Sprintf("%%%02X", c))
		}
	}
	return b.String()
}

func defaultNonce() string {
	return strconv.FormatInt(time.Now().UnixNano(), 36)
}
