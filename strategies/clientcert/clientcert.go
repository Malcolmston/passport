// Package clientcert implements TLS client-certificate (mutual TLS)
// authentication. It reads the peer's leaf certificate from the request's TLS
// connection state and hands it to a user-supplied Verify function that maps
// the certificate to a user (for example, by looking up its subject or
// fingerprint). Requests without a client certificate fail.
package clientcert

import (
	"crypto/x509"
	"errors"
	"net/http"

	"github.com/malcolmston/passport"
)

// ErrRejected is a convenience sentinel a Verify func may return to reject an
// otherwise valid certificate (treated as an authentication failure).
var ErrRejected = errors.New("certificate rejected")

// VerifyFunc maps a verified client certificate to a user.
type VerifyFunc func(cert *x509.Certificate) (user any, err error)

// Options configures the clientcert Strategy.
type Options struct {
	// Verify maps the peer leaf certificate to a user.
	Verify VerifyFunc
}

// Strategy authenticates requests presenting a TLS client certificate.
type Strategy struct {
	verify VerifyFunc
}

// New creates a clientcert Strategy.
func New(opts Options) *Strategy {
	return &Strategy{verify: opts.Verify}
}

// Name returns "client-cert".
func (s *Strategy) Name() string { return "client-cert" }

// Authenticate implements passport.Strategy.
func (s *Strategy) Authenticate(c *passport.Context, r *http.Request) {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		c.Fail("No client certificate", http.StatusUnauthorized)
		return
	}
	cert := r.TLS.PeerCertificates[0]
	user, err := s.verify(cert)
	if err != nil {
		if errors.Is(err, ErrRejected) {
			c.Fail("Certificate rejected", http.StatusUnauthorized)
			return
		}
		c.Error(err)
		return
	}
	if user == nil {
		c.Fail("Certificate rejected", http.StatusUnauthorized)
		return
	}
	c.Success(user)
}
