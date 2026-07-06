// Package clientcert implements TLS client-certificate (mutual TLS)
// authentication for the passport port, comparable to Passport.js's
// passport-client-cert. Rather than reading a credential from the request body
// or headers, it authenticates the client by the X.509 certificate presented
// during the TLS handshake.
//
// Use it for high-assurance service-to-service calls, zero-trust internal
// networks, and device or partner integrations where each caller holds a client
// certificate issued by a trusted CA. It is stateless and normally mounted with
// passport.Options{Session: false}, since the certificate re-authenticates every
// connection.
//
// The strategy reads the peer's leaf certificate from r.TLS.PeerCertificates and
// hands it to a user-supplied VerifyFunc that maps it to an application user —
// typically by inspecting the subject common name, an email SAN, or a
// fingerprint and looking the principal up in a directory. If the request
// arrived without TLS or without a client certificate it fails with a 401 before
// VerifyFunc runs.
//
// The VerifyFunc contract has three outcomes: a non-nil user authenticates the
// request; (nil, nil) or (nil, ErrRejected) rejects an otherwise valid
// certificate as an authentication failure; and (nil, err) is an internal error.
// Crucially, cryptographic verification of the certificate chain is the TLS
// layer's job: the server must be configured to request and verify client
// certificates (for example a tls.Config with ClientAuth set to
// RequireAndVerifyClientCert and an appropriate ClientCAs pool). This strategy
// makes the authorization decision — which verified identity maps to which user —
// not the chain validation.
//
// Parity: like passport-client-cert this turns a verified client certificate into
// a user via a callback, but it relies on Go's crypto/tls for chain verification
// and leaves certificate revocation (CRL/OCSP) and CA configuration to the
// server's tls.Config.
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
