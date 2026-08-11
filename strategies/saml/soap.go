package saml

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// This file implements the SOAP 1.1 back-channel the SAML 2.0 SOAP binding
// (OASIS SAML 2.0 Bindings, section 3.2) uses. It is the transport underneath
// the HTTP-Artifact binding in artifact.go: unlike every other binding in this
// package, the message does not travel through the user's browser but over a
// direct HTTPS connection from this service provider to the identity provider.
//
// A back-channel call is an outbound HTTP request whose *content* is influenced
// by an untrusted party, so it is hardened as such:
//
//   - The URL is never taken from the message. It comes from configuration or
//     from signed IdP metadata; see ArtifactOptions.ArtifactResolutionURL. An
//     endpoint chosen by the peer would make this a server-side request forgery
//     primitive.
//   - The client always has a timeout. An identity provider that accepts the
//     connection and then never answers would otherwise pin a request goroutine
//     and a file descriptor indefinitely.
//   - The response body is capped before it is read, so a hostile or broken
//     responder cannot exhaust memory.
//   - Redirects may not change host or downgrade the scheme, and are bounded.
//     Following a cross-host redirect would hand the destination back to the
//     peer, which is the same SSRF hole the first rule closes.
//   - TLS verification may not be disabled. A supplied client that turns it off
//     is rejected at construction rather than used.

// nsSOAP11 is the SOAP 1.1 envelope namespace.
const nsSOAP11 = "http://schemas.xmlsoap.org/soap/envelope/"

// SOAPAction is the SOAPAction header value the SAML SOAP binding mandates for
// SAML protocol messages.
const SOAPAction = "http://www.oasis-open.org/committees/security"

// Back-channel defaults.
const (
	// DefaultSOAPTimeout is the timeout applied to a back-channel call when
	// neither ArtifactOptions.Timeout nor the supplied client sets one.
	DefaultSOAPTimeout = 10 * time.Second
	// maxSOAPRedirects bounds how many redirects a back-channel call follows.
	maxSOAPRedirects = 5
)

// ErrSOAPFault is the sentinel every SOAP fault wraps, so that
// errors.Is(err, ErrSOAPFault) answers "the peer returned a fault" without the
// caller having to type-assert.
var ErrSOAPFault = errors.New("saml: SOAP fault")

// ErrInsecureTLS is returned when the supplied HTTP client would skip TLS
// certificate verification on the back channel.
var ErrInsecureTLS = errors.New("saml: back-channel HTTP client disables TLS certificate verification")

// SOAPFault is a soap:Fault returned by the identity provider. It is an error,
// not a panic and not a silently empty result: a fault means the resolution did
// not happen and no assertion may be derived from it.
type SOAPFault struct {
	// Code is the faultcode QName as written by the peer, e.g. "soap:Client".
	Code string
	// String is the human-readable faultstring.
	String string
	// Actor is the faultactor URI, empty when the peer omitted it.
	Actor string
}

// Error implements error.
func (f *SOAPFault) Error() string {
	msg := "saml: SOAP fault"
	if f.Code != "" {
		msg += " " + f.Code
	}
	if f.String != "" {
		msg += ": " + f.String
	}
	return msg
}

// Unwrap makes errors.Is(err, ErrSOAPFault) report true for any fault.
func (f *SOAPFault) Unwrap() error { return ErrSOAPFault }

// soapEnvelope wraps a SAML protocol message in a SOAP 1.1 envelope.
func soapEnvelope(message string) []byte {
	var sb strings.Builder
	sb.WriteString(`<?xml version="1.0" encoding="UTF-8"?>`)
	sb.WriteString(`<soap:Envelope xmlns:soap="` + nsSOAP11 + `"><soap:Body>`)
	sb.WriteString(message)
	sb.WriteString(`</soap:Body></soap:Envelope>`)
	return []byte(sb.String())
}

// soapClient performs hardened SOAP 1.1 calls over the back channel.
type soapClient struct {
	client   *http.Client
	maxBytes int
	maxDepth int
}

// newSOAPClient derives a hardened client from base, which may be nil.
//
// base is never mutated: the struct is copied so that filling in a missing
// timeout or redirect policy cannot surprise a caller who shares one client
// across their whole program. The underlying Transport, and therefore its
// connection pool, is still shared.
func newSOAPClient(base *http.Client, timeout time.Duration, maxBytes, maxDepth int) (*soapClient, error) {
	c := &http.Client{}
	if base != nil {
		copied := *base
		c = &copied
	}
	if c.Transport != nil {
		if err := checkTransportTLS(c.Transport); err != nil {
			return nil, err
		}
	}
	if timeout > 0 {
		c.Timeout = timeout
	} else if c.Timeout <= 0 {
		c.Timeout = DefaultSOAPTimeout
	}
	if c.CheckRedirect == nil {
		c.CheckRedirect = checkBackChannelRedirect
	}
	if maxBytes <= 0 {
		maxBytes = defaultMaxResponseBytes
	}
	if maxDepth <= 0 {
		maxDepth = defaultMaxDepth
	}
	return &soapClient{client: c, maxBytes: maxBytes, maxDepth: maxDepth}, nil
}

// checkTransportTLS refuses a transport configured to skip certificate
// verification. Without verification the back channel authenticates nothing, and
// the ArtifactResponse signature is the only thing left standing between an
// on-path attacker and a forged assertion.
func checkTransportTLS(rt http.RoundTripper) error {
	t, ok := rt.(*http.Transport)
	if !ok {
		// A custom RoundTripper cannot be inspected. Its author is
		// responsible for its TLS configuration.
		return nil
	}
	if t.TLSClientConfig != nil && t.TLSClientConfig.InsecureSkipVerify {
		return ErrInsecureTLS
	}
	return nil
}

// checkBackChannelRedirect is the default redirect policy: bounded, same-host,
// and never a downgrade from https.
func checkBackChannelRedirect(req *http.Request, via []*http.Request) error {
	if len(via) >= maxSOAPRedirects {
		return fmt.Errorf("saml: back-channel call followed more than %d redirects", maxSOAPRedirects)
	}
	prev := via[len(via)-1]
	if !strings.EqualFold(req.URL.Host, prev.URL.Host) {
		return fmt.Errorf("saml: back-channel redirect to a different host %q is refused", req.URL.Host)
	}
	if strings.EqualFold(prev.URL.Scheme, "https") && !strings.EqualFold(req.URL.Scheme, "https") {
		return fmt.Errorf("saml: back-channel redirect downgrades to %q", req.URL.Scheme)
	}
	return nil
}

// call POSTs message inside a SOAP envelope to url and returns the single
// element carried in the response's soap:Body.
//
// A soap:Fault is returned as a *SOAPFault error. So is a non-2xx status that
// carries no parsable fault: the one thing this never does is return a nil error
// alongside a body that was not understood.
func (c *soapClient) call(ctx context.Context, url string, message string) (*xnode, error) {
	if url == "" {
		return nil, errors.New("saml: no back-channel endpoint configured")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	body := soapEnvelope(message)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("saml: building back-channel request: %w", err)
	}
	req.Header.Set("Content-Type", "text/xml; charset=utf-8")
	req.Header.Set("SOAPAction", `"`+SOAPAction+`"`)
	req.ContentLength = int64(len(body))

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("saml: back-channel request failed: %w", err)
	}
	defer func() {
		// Drain a bounded amount so the connection can be reused, then close.
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		_ = resp.Body.Close()
	}()

	// The declared length is checked before a single byte is read, so an
	// honestly-declared oversized body costs nothing at all.
	if resp.ContentLength > int64(c.maxBytes) {
		return nil, fmt.Errorf("%w: back-channel response declares %d bytes", ErrTooLarge, resp.ContentLength)
	}
	// One byte past the cap, so an over-long body is detected rather than
	// silently truncated into something that might still parse.
	data, err := io.ReadAll(io.LimitReader(resp.Body, int64(c.maxBytes)+1))
	if err != nil {
		return nil, fmt.Errorf("saml: reading back-channel response: %w", err)
	}
	if len(data) > c.maxBytes {
		return nil, fmt.Errorf("%w: back-channel response exceeds %d bytes", ErrTooLarge, c.maxBytes)
	}

	// SOAP 1.1 carries a fault with status 500, so that status still has to be
	// parsed. Anything else non-2xx is reported as-is.
	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
	case resp.StatusCode == http.StatusInternalServerError:
	default:
		return nil, fmt.Errorf("saml: back-channel responder returned HTTP %d", resp.StatusCode)
	}

	elem, err := parseSOAPBody(data, c.maxDepth)
	if err != nil {
		if resp.StatusCode != http.StatusInternalServerError {
			return nil, err
		}
		return nil, fmt.Errorf("saml: back-channel responder returned HTTP %d: %w", resp.StatusCode, err)
	}
	return elem, nil
}

// parseSOAPBody parses a SOAP 1.1 envelope with the package's strict parser and
// returns the single element inside soap:Body, or a *SOAPFault.
func parseSOAPBody(data []byte, maxDepth int) (*xnode, error) {
	root, err := parseXML(data, maxDepth)
	if err != nil {
		return nil, fmt.Errorf("saml: parsing SOAP response: %w", err)
	}
	if !root.is(nsSOAP11, "Envelope") {
		return nil, fmt.Errorf("saml: SOAP response root is <%s>, expected soap:Envelope", root.local)
	}
	soapBody, err := root.onlyChild(nsSOAP11, "Body")
	if err != nil {
		return nil, err
	}
	if fault, err := soapBody.optionalChild(nsSOAP11, "Fault"); err != nil {
		return nil, err
	} else if fault != nil {
		return nil, readSOAPFault(fault)
	}

	var elems []*xnode
	for _, ch := range soapBody.children {
		if ch.kind == nodeElement {
			elems = append(elems, ch)
		}
	}
	if len(elems) != 1 {
		return nil, fmt.Errorf("saml: soap:Body carries %d elements, expected exactly 1", len(elems))
	}
	return elems[0], nil
}

// readSOAPFault turns a soap:Fault element into a *SOAPFault. Its children are
// unqualified in SOAP 1.1, which is why they are looked up with an empty
// namespace URI.
func readSOAPFault(fault *xnode) error {
	f := &SOAPFault{}
	for _, ch := range fault.children {
		if ch.kind != nodeElement {
			continue
		}
		switch {
		case ch.is("", "faultcode"):
			f.Code = strings.TrimSpace(ch.textContent())
		case ch.is("", "faultstring"):
			f.String = strings.TrimSpace(ch.textContent())
		case ch.is("", "faultactor"):
			f.Actor = strings.TrimSpace(ch.textContent())
		}
	}
	return f
}
