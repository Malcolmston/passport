package clientcert_test

import (
	"crypto/x509"
	"fmt"
	"log"
	"net/http"

	"github.com/malcolmston/passport"
	"github.com/malcolmston/passport/strategies/clientcert"
)

// ExampleNew shows the full wiring for the mutual-TLS (mTLS) client-certificate
// strategy: register it with passport, then guard a route with it. The strategy
// reads the peer's leaf certificate from the TLS connection and hands it to the
// verify func, which maps it to your application user. The strategy registers
// under the name "client-cert".
//
// The server must request client certificates during the TLS handshake, e.g.
// with tls.Config{ClientAuth: tls.RequireAndVerifyClientCert}.
func ExampleNew() {
	p := passport.New()

	// The verify func inspects the verified client certificate (for example the
	// subject common name) and returns the authenticated user. Return
	// clientcert.ErrRejected (or a nil user) to reject the request.
	p.Use(clientcert.New(clientcert.Options{
		Verify: func(cert *x509.Certificate) (user any, err error) {
			if cert.Subject.CommonName == "" {
				return nil, clientcert.ErrRejected
			}
			return cert.Subject.CommonName, nil
		},
	}))

	// The protected handler only runs after successful authentication.
	protected := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprintf(w, "hello, %v", passport.User(r))
	})

	mux := http.NewServeMux()
	// mTLS is stateless: skip session creation on success.
	mux.Handle("/secure", p.Authenticate("client-cert", passport.Options{Session: false})(protected))

	handler := passport.Chain(mux, p.Initialize(), p.Session())

	// Serve over HTTPS, requesting and verifying client certificates. The cert
	// and key identify the server; a real deployment also configures a
	// ClientCAs pool that the client certs are verified against.
	server := &http.Server{Addr: ":3000", Handler: handler}
	log.Fatal(server.ListenAndServeTLS("server.crt", "server.key"))
}
