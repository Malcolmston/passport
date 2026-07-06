// Package clientcredentials implements OAuth2 client-credentials style
// authentication for the passport port. In the client-credentials grant (RFC
// 6749 §4.4) there is no end user and no browser: a client application proves its
// own identity with a client_id and client_secret. This strategy reads that pair
// from a request and hands it to a user-supplied VerifyFunc that decides whether
// the client is authentic.
//
// Use it for machine-to-machine (M2M) APIs -- a backend service, a cron job, a
// webhook sender, or a partner integration calling your endpoints. Because there
// is no interactive login, there is no redirect and no user-facing frontend;
// clients simply attach their credentials to every request. Pair the strategy
// with passport.Options{Session: false} so no session cookie is created for what
// is inherently a stateless call.
//
// Credential extraction tries two locations in order. First it looks for an HTTP
// Basic Authorization header (RFC 6749 §2.3.1), base64-decoding the
// "id:secret" value. If that is absent, it falls back to reading client_id and
// client_secret from the request's form body (application/x-www-form-urlencoded).
// If neither yields a client id, the strategy fails with a "Basic" challenge and
// HTTP 401.
//
// The VerifyFunc contract governs the outcome. Returning a non-nil user
// authenticates the client and that value becomes passport.User. Returning a nil
// user (with a nil error) rejects the request as an authentication failure,
// responding "invalid_client" with HTTP 401; returning the ErrInvalidClient
// sentinel does the same and is a convenient way to signal bad credentials. Any
// other non-nil error is treated as an internal error and reported via
// Context.Error rather than as a normal auth failure.
//
// Parity note: this is not a full OAuth2 authorization server -- it does not
// issue tokens, mint JWTs, or track scopes. It authenticates the client on each
// request from the credentials it presents, which is the piece Passport-style
// middleware is responsible for; layer your own token issuance on top if you need
// bearer tokens. The strategy registers under the name "client-credentials".
package clientcredentials

import (
	"encoding/base64"
	"errors"
	"net/http"
	"strings"

	"github.com/malcolmston/passport"
)

// ErrInvalidClient is a convenience sentinel a Verify func may return to signal
// invalid client credentials (treated as an authentication failure).
var ErrInvalidClient = errors.New("invalid client")

// VerifyFunc validates a client id/secret pair, returning the authenticated
// client (user) on success.
type VerifyFunc func(id, secret string) (user any, err error)

// Strategy authenticates OAuth2 clients using the client-credentials grant.
type Strategy struct {
	verify VerifyFunc
}

// New creates a clientcredentials Strategy.
func New(verify VerifyFunc) *Strategy {
	return &Strategy{verify: verify}
}

// Name returns "client-credentials".
func (s *Strategy) Name() string { return "client-credentials" }

// Authenticate implements passport.Strategy.
func (s *Strategy) Authenticate(c *passport.Context, r *http.Request) {
	id, secret, ok := credentials(r)
	if !ok {
		c.Fail("Basic", http.StatusUnauthorized)
		return
	}
	user, err := s.verify(id, secret)
	if err != nil {
		if errors.Is(err, ErrInvalidClient) {
			c.Fail("invalid_client", http.StatusUnauthorized)
			return
		}
		c.Error(err)
		return
	}
	if user == nil {
		c.Fail("invalid_client", http.StatusUnauthorized)
		return
	}
	c.Success(user)
}

// credentials extracts the client id/secret from the Basic header first, then
// falls back to the form body.
func credentials(r *http.Request) (id, secret string, ok bool) {
	if h := r.Header.Get("Authorization"); len(h) >= 6 && strings.EqualFold(h[:6], "basic ") {
		if decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(h[6:])); err == nil {
			creds := string(decoded)
			if i := strings.IndexByte(creds, ':'); i >= 0 {
				return creds[:i], creds[i+1:], true
			}
		}
	}
	if err := r.ParseForm(); err == nil {
		id = r.PostFormValue("client_id")
		secret = r.PostFormValue("client_secret")
		if id != "" {
			return id, secret, true
		}
	}
	return "", "", false
}
