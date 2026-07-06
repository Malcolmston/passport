package clientcert_test

import (
	"crypto/x509"
	"fmt"
	"log"
	"net/http"

	"github.com/malcolmston/passport"
	"github.com/malcolmston/passport/strategies/clientcert"
)

// ExampleNew shows the full backend wiring for the mutual-TLS (mTLS)
// client-certificate strategy. It registers the strategy with a VerifyFunc that
// inspects the verified client certificate (here the subject common name) and
// returns the authenticated user, then mounts it on "/secure" with
// passport.Options{Session: false} because the certificate re-authenticates every
// connection. The strategy registers under the name "client-cert" and reads the
// peer's leaf certificate from the request's TLS state, so the request must
// arrive over HTTPS with a client certificate present. Crucially the server must
// be configured to request and verify client certificates during the handshake —
// for example tls.Config{ClientAuth: tls.RequireAndVerifyClientCert} with an
// appropriate ClientCAs pool — because chain validation is the TLS layer's
// responsibility, not the strategy's. Only a certificate that both the TLS layer
// accepts and VerifyFunc maps to a non-nil user reaches the protected handler.
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

// Example_frontend serves an informational page for the mutual-TLS strategy and
// shows the small amount the browser side actually does. With mTLS the client
// certificate is negotiated by the browser and operating system during the TLS
// handshake, not by JavaScript: when the server requests a certificate the
// browser prompts the user to choose one from its keystore, and that selection
// authenticates every subsequent request on the connection. The page therefore
// just calls fetch("/secure") — no Authorization header or token is set, because
// the identity travels in the TLS layer that fetch cannot see or control. For
// this to work the certificate must be installed in the browser/OS keystore and
// issued by a CA the server trusts via its ClientCAs pool. The response text is
// written into the page so the result of the certificate-authenticated call is
// visible.
func Example_frontend() {
	const page = `<!doctype html>
<html>
<head><title>Client certificate demo</title></head>
<body>
  <p>Your browser presents a client certificate during the TLS handshake.</p>
  <pre id="out">loading...</pre>
  <script>
    fetch("/secure")
      .then(function (r) { return r.text(); })
      .then(function (t) { document.getElementById("out").textContent = t; });
  </script>
</body>
</html>`

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(page))
	})

	log.Fatal(http.ListenAndServe(":8080", mux))
}
