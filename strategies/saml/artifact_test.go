package saml

import (
	"context"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// This file covers the HTTP-Artifact binding and the SOAP back channel. Every
// test is self-contained: keys are generated in-process by newTestIdP, the
// identity provider's artifact resolution service is an httptest server, and
// the clock is injected, so nothing here touches the network or the wall clock.

const (
	testArtifactSPEntityID = "https://sp.example.com/metadata"
	testArtifactEndpointIx = 3
)

// artifactIdP is a mock identity provider artifact resolution service.
type artifactIdP struct {
	t   *testing.T
	idp *testIdP

	// server is the httptest server; URL is its address.
	server *httptest.Server
	URL    string

	// resolveRequests records every ArtifactResolve received, in order.
	resolveRequests []*xnode
	// calls counts every request the service received, successful or not.
	calls int

	// The knobs each test turns.
	signArtifactResponse bool
	innerXML             string
	status               string
	issuer               string
	inResponseToOverride string
	respond              func(w http.ResponseWriter, r *http.Request) bool
}

// newArtifactIdP starts a resolution service returning a signed
// ArtifactResponse wrapping innerXML.
func newArtifactIdP(t *testing.T, idp *testIdP, innerXML string) *artifactIdP {
	t.Helper()
	a := &artifactIdP{
		t:                    t,
		idp:                  idp,
		signArtifactResponse: true,
		innerXML:             innerXML,
		status:               StatusSuccess,
		issuer:               testIssuer,
	}
	a.server = httptest.NewServer(http.HandlerFunc(a.handle))
	t.Cleanup(a.server.Close)
	a.URL = a.server.URL
	return a
}

func (a *artifactIdP) handle(w http.ResponseWriter, r *http.Request) {
	a.calls++
	if a.respond != nil && a.respond(w, r) {
		return
	}
	if r.Method != http.MethodPost {
		a.t.Errorf("artifact resolution used %s, want POST", r.Method)
	}
	if ct := r.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/xml") {
		a.t.Errorf("Content-Type = %q", ct)
	}
	if r.Header.Get("SOAPAction") == "" {
		a.t.Error("SOAPAction header is missing")
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		a.t.Errorf("reading ArtifactResolve: %v", err)
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	resolve, err := parseSOAPBody(body, defaultMaxDepth)
	if err != nil {
		a.t.Errorf("parsing ArtifactResolve: %v", err)
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if !resolve.is(nsSAMLProtocol, "ArtifactResolve") {
		a.t.Errorf("back channel carried <%s>", resolve.local)
	}
	a.resolveRequests = append(a.resolveRequests, resolve)

	id, _ := resolve.attrValue("", "ID")
	if a.inResponseToOverride != "" {
		id = a.inResponseToOverride
	}
	w.Header().Set("Content-Type", "text/xml; charset=utf-8")
	_, _ = w.Write(soapEnvelope(a.artifactResponse(id)))
}

// artifactResponse renders the samlp:ArtifactResponse, signing it unless the
// test asked for an unsigned one.
func (a *artifactIdP) artifactResponse(inResponseTo string) string {
	a.t.Helper()
	const id = "_artifactresponse1"
	var sb strings.Builder
	sb.WriteString(`<samlp:ArtifactResponse xmlns:samlp="` + nsSAMLProtocol + `"`)
	sb.WriteString(` xmlns:saml="` + nsSAMLAssertion + `"`)
	sb.WriteString(` ID="` + id + `" Version="2.0"`)
	sb.WriteString(` IssueInstant="` + iso(testNow) + `"`)
	sb.WriteString(` InResponseTo="` + inResponseTo + `">`)
	sb.WriteString(`<saml:Issuer>` + a.issuer + `</saml:Issuer>`)
	sb.WriteString(signatureMarker)
	sb.WriteString(`<samlp:Status><samlp:StatusCode Value="` + a.status + `"/></samlp:Status>`)
	sb.WriteString(a.innerXML)
	sb.WriteString(`</samlp:ArtifactResponse>`)

	tmpl := sb.String()
	if !a.signArtifactResponse {
		return strings.Replace(tmpl, signatureMarker, "", 1)
	}
	signed, err := signEnveloped(tmpl, id, a.idp.key, a.idp.cert, SigAlgRSASHA256, defaultMaxDepth)
	if err != nil {
		a.t.Fatalf("signing ArtifactResponse: %v", err)
	}
	return string(signed)
}

// artifactOptions returns options wired to this mock IdP.
func (a *artifactIdP) options() ArtifactOptions {
	return ArtifactOptions{
		EntityID:              testArtifactSPEntityID,
		IdPEntityID:           testIssuer,
		ArtifactResolutionURL: a.URL,
		IdPCertificates:       []*x509.Certificate{a.idp.cert},
		Clock:                 testClock,
	}
}

// mustArtifact builds a valid artifact for testIssuer.
func mustArtifact(t *testing.T) *Artifact {
	t.Helper()
	art, err := NewArtifact(testIssuer, testArtifactEndpointIx)
	if err != nil {
		t.Fatalf("NewArtifact: %v", err)
	}
	return art
}

// TestArtifactRoundTrip is the whole binding end to end: a browser-supplied
// SAMLart is parsed, resolved over the back channel and validated into an
// authenticated assertion.
//
// Against the pre-change package this test does not compile — there was no
// artifact code at all — so "fails before the change" is unconditional for
// every test in this file except the xs:duration ones, which are called out
// individually.
func TestArtifactRoundTrip(t *testing.T) {
	idp := newTestIdP(t, "rsa")
	f := newFixture(idp)
	f.signTarget = "response"
	server := newArtifactIdP(t, idp, f.xml(t))

	sp := newTestIdP(t, "rsa") // the SP's own signing key
	opts := server.options()
	opts.SigningKey = sp.key
	opts.SigningCertificate = sp.cert

	r, err := NewArtifactResolver(opts)
	if err != nil {
		t.Fatalf("NewArtifactResolver: %v", err)
	}
	art := mustArtifact(t)

	assertion, err := r.ResolveAssertion(context.Background(), art.String(), f.strategy())
	if err != nil {
		t.Fatalf("ResolveAssertion: %v", err)
	}
	if assertion.NameID != testNameID {
		t.Errorf("NameID = %q, want %q", assertion.NameID, testNameID)
	}
	if !assertion.ResponseSigned {
		t.Error("assertion did not come from a signed response")
	}

	// The ArtifactResolve the IdP saw must name this SP, quote the artifact
	// verbatim, and carry a signature over itself.
	if len(server.resolveRequests) != 1 {
		t.Fatalf("resolution service called %d times, want 1", len(server.resolveRequests))
	}
	got := server.resolveRequests[0]
	issuer, err := got.onlyChild(nsSAMLAssertion, "Issuer")
	if err != nil {
		t.Fatalf("ArtifactResolve Issuer: %v", err)
	}
	if v := strings.TrimSpace(issuer.textContent()); v != testArtifactSPEntityID {
		t.Errorf("ArtifactResolve Issuer = %q", v)
	}
	artElem, err := got.onlyChild(nsSAMLProtocol, "Artifact")
	if err != nil {
		t.Fatalf("ArtifactResolve Artifact: %v", err)
	}
	if v := strings.TrimSpace(artElem.textContent()); v != art.String() {
		t.Errorf("resolved artifact = %q, want %q", v, art.String())
	}
	sig, err := got.onlyChild(nsDSig, "Signature")
	if err != nil {
		t.Fatalf("ArtifactResolve is not signed: %v", err)
	}
	verified, err := verifySignature(got, sig, []*x509.Certificate{sp.cert}, false)
	if err != nil {
		t.Fatalf("ArtifactResolve signature does not verify: %v", err)
	}
	if verified.element != got {
		t.Error("ArtifactResolve signature does not cover the request")
	}
	if dest, _ := got.attrValue("", "Destination"); dest != server.URL {
		t.Errorf("Destination = %q, want %q", dest, server.URL)
	}
}

// TestArtifactResolveUnsignedWithoutKey checks that no signing key simply means
// an unsigned ArtifactResolve rather than an error: many identity providers do
// not require one.
func TestArtifactResolveUnsignedWithoutKey(t *testing.T) {
	idp := newTestIdP(t, "rsa")
	f := newFixture(idp)
	f.signTarget = "response"
	server := newArtifactIdP(t, idp, f.xml(t))

	r, err := NewArtifactResolver(server.options())
	if err != nil {
		t.Fatalf("NewArtifactResolver: %v", err)
	}
	if _, err := r.Resolve(context.Background(), mustArtifact(t).String()); err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if sig, _ := server.resolveRequests[0].optionalChild(nsDSig, "Signature"); sig != nil {
		t.Error("ArtifactResolve is signed although no key was configured")
	}
}

// TestParseArtifact covers the wire format: the type code, the length, and the
// base64 wrapper.
func TestParseArtifact(t *testing.T) {
	valid := mustArtifact(t)

	t.Run("valid", func(t *testing.T) {
		got, err := ParseArtifact(valid.String())
		if err != nil {
			t.Fatalf("ParseArtifact: %v", err)
		}
		if got.TypeCode != ArtifactTypeCode0004 {
			t.Errorf("TypeCode = 0x%04x", got.TypeCode)
		}
		if got.EndpointIndex != testArtifactEndpointIx {
			t.Errorf("EndpointIndex = %d", got.EndpointIndex)
		}
		if got.SourceID != SourceIDFor(testIssuer) {
			t.Error("SourceID does not match SHA-1 of the entity ID")
		}
		if got.MessageHandle != valid.MessageHandle {
			t.Error("MessageHandle was not round-tripped")
		}
		if got.String() != valid.String() {
			t.Error("String() does not round-trip")
		}
	})

	t.Run("wrong TypeCode", func(t *testing.T) {
		// Type 0x0003 is SAML 1.x's artifact format; anything else is simply
		// unknown. Either way, guessing is not an option.
		for _, code := range []uint16{0x0000, 0x0001, 0x0003, 0x0005, 0xffff} {
			raw := append([]byte(nil), valid.Raw...)
			binary.BigEndian.PutUint16(raw[0:2], code)
			_, err := ParseArtifact(base64.StdEncoding.EncodeToString(raw))
			if !errors.Is(err, ErrMalformedArtifact) {
				t.Errorf("type 0x%04x: err = %v, want ErrMalformedArtifact", code, err)
			}
		}
	})

	t.Run("wrong length", func(t *testing.T) {
		for _, n := range []int{0, 1, 4, 43, 45, 88} {
			raw := make([]byte, n)
			if n >= 2 {
				binary.BigEndian.PutUint16(raw[0:2], ArtifactTypeCode0004)
			}
			_, err := ParseArtifact(base64.StdEncoding.EncodeToString(raw))
			if !errors.Is(err, ErrMalformedArtifact) {
				t.Errorf("%d octets: err = %v, want ErrMalformedArtifact", n, err)
			}
		}
	})

	t.Run("not base64", func(t *testing.T) {
		for _, s := range []string{"", "   ", "!!!!", "not base64 at all"} {
			if _, err := ParseArtifact(s); !errors.Is(err, ErrMalformedArtifact) {
				t.Errorf("%q: err = %v, want ErrMalformedArtifact", s, err)
			}
		}
	})
}

// TestArtifactSourceIDMismatch is the check that stops an attacker pointing the
// service provider at an identity provider of their choosing. The artifact is
// perfectly well formed; it just names somebody else.
func TestArtifactSourceIDMismatch(t *testing.T) {
	idp := newTestIdP(t, "rsa")
	f := newFixture(idp)
	f.signTarget = "response"
	server := newArtifactIdP(t, idp, f.xml(t))

	r, err := NewArtifactResolver(server.options())
	if err != nil {
		t.Fatalf("NewArtifactResolver: %v", err)
	}
	evil, err := NewArtifact("https://evil.example.com/entity", 0)
	if err != nil {
		t.Fatalf("NewArtifact: %v", err)
	}
	_, err = r.Resolve(context.Background(), evil.String())
	if !errors.Is(err, ErrArtifactSourceID) {
		t.Fatalf("err = %v, want ErrArtifactSourceID", err)
	}
	// And crucially the back channel was never used: an artifact that fails
	// this check must not even generate traffic.
	if server.calls != 0 {
		t.Errorf("resolution service was called %d times for a foreign artifact", server.calls)
	}
}

// TestArtifactUnsignedResponses rejects both an unsigned envelope and an
// unsigned payload. TLS on the back channel authenticates the endpoint, not the
// message, so neither may be accepted on the strength of the transport.
func TestArtifactUnsignedResponses(t *testing.T) {
	idp := newTestIdP(t, "rsa")

	t.Run("unsigned ArtifactResponse", func(t *testing.T) {
		f := newFixture(idp)
		f.signTarget = "response" // the payload IS signed
		server := newArtifactIdP(t, idp, f.xml(t))
		server.signArtifactResponse = false

		r, err := NewArtifactResolver(server.options())
		if err != nil {
			t.Fatalf("NewArtifactResolver: %v", err)
		}
		_, err = r.Resolve(context.Background(), mustArtifact(t).String())
		if !errors.Is(err, ErrNoSignature) {
			t.Fatalf("err = %v, want ErrNoSignature", err)
		}
	})

	t.Run("unsigned inner Response", func(t *testing.T) {
		f := newFixture(idp)
		f.signTarget = "" // the envelope IS signed, the payload is not
		server := newArtifactIdP(t, idp, f.xml(t))

		r, err := NewArtifactResolver(server.options())
		if err != nil {
			t.Fatalf("NewArtifactResolver: %v", err)
		}
		_, err = r.Resolve(context.Background(), mustArtifact(t).String())
		if !errors.Is(err, ErrNoSignature) {
			t.Fatalf("err = %v, want ErrNoSignature", err)
		}
	})

	t.Run("no certificate configured", func(t *testing.T) {
		f := newFixture(idp)
		f.signTarget = "response"
		server := newArtifactIdP(t, idp, f.xml(t))
		opts := server.options()
		opts.IdPCertificates = nil

		r, err := NewArtifactResolver(opts)
		if err != nil {
			t.Fatalf("NewArtifactResolver: %v", err)
		}
		_, err = r.Resolve(context.Background(), mustArtifact(t).String())
		if !errors.Is(err, ErrNoCertificates) {
			t.Fatalf("err = %v, want ErrNoCertificates", err)
		}
	})

	t.Run("wrong signing key", func(t *testing.T) {
		f := newFixture(idp)
		f.signTarget = "response"
		other := newTestIdP(t, "rsa")
		server := newArtifactIdP(t, other, f.xml(t)) // envelope signed by a stranger
		opts := server.options()
		opts.IdPCertificates = []*x509.Certificate{idp.cert}

		r, err := NewArtifactResolver(opts)
		if err != nil {
			t.Fatalf("NewArtifactResolver: %v", err)
		}
		if _, err := r.Resolve(context.Background(), mustArtifact(t).String()); err == nil {
			t.Fatal("a foreign signature was accepted")
		}
	})
}

// TestArtifactSOAPFault handles the error path the specification actually
// defines for a resolution the IdP will not perform. It must surface as an
// error, never as a panic and never as an empty success.
func TestArtifactSOAPFault(t *testing.T) {
	idp := newTestIdP(t, "rsa")
	f := newFixture(idp)
	f.signTarget = "response"
	server := newArtifactIdP(t, idp, f.xml(t))
	server.respond = func(w http.ResponseWriter, r *http.Request) bool {
		w.Header().Set("Content-Type", "text/xml; charset=utf-8")
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`<?xml version="1.0"?>` +
			`<soap:Envelope xmlns:soap="` + nsSOAP11 + `"><soap:Body><soap:Fault>` +
			`<faultcode>soap:Client</faultcode>` +
			`<faultstring>artifact is unknown</faultstring>` +
			`<faultactor>https://idp.example.com/ars</faultactor>` +
			`</soap:Fault></soap:Body></soap:Envelope>`))
		return true
	}

	r, err := NewArtifactResolver(server.options())
	if err != nil {
		t.Fatalf("NewArtifactResolver: %v", err)
	}
	_, err = r.Resolve(context.Background(), mustArtifact(t).String())
	if !errors.Is(err, ErrSOAPFault) {
		t.Fatalf("err = %v, want ErrSOAPFault", err)
	}
	var fault *SOAPFault
	if !errors.As(err, &fault) {
		t.Fatalf("err = %v, want a *SOAPFault", err)
	}
	if fault.Code != "soap:Client" || fault.String != "artifact is unknown" ||
		fault.Actor != "https://idp.example.com/ars" {
		t.Errorf("fault = %+v", fault)
	}
	if !strings.Contains(fault.Error(), "artifact is unknown") {
		t.Errorf("Error() = %q", fault.Error())
	}
}

// TestArtifactBackChannelFailures covers everything the peer can do to the
// transport short of answering correctly.
func TestArtifactBackChannelFailures(t *testing.T) {
	idp := newTestIdP(t, "rsa")
	f := newFixture(idp)
	f.signTarget = "response"
	inner := f.xml(t)

	t.Run("oversized response", func(t *testing.T) {
		server := newArtifactIdP(t, idp, inner)
		server.respond = func(w http.ResponseWriter, r *http.Request) bool {
			w.Header().Set("Content-Type", "text/xml; charset=utf-8")
			// One contiguous write, so net/http sets Content-Length and the
			// declared-size check fires before the body is read at all.
			_, _ = w.Write([]byte(strings.Repeat("A", 200_000)))
			return true
		}
		opts := server.options()
		opts.MaxResponseBytes = 4096

		r, err := NewArtifactResolver(opts)
		if err != nil {
			t.Fatalf("NewArtifactResolver: %v", err)
		}
		_, err = r.Resolve(context.Background(), mustArtifact(t).String())
		if !errors.Is(err, ErrTooLarge) {
			t.Fatalf("err = %v, want ErrTooLarge", err)
		}
	})

	t.Run("oversized chunked response", func(t *testing.T) {
		server := newArtifactIdP(t, idp, inner)
		server.respond = func(w http.ResponseWriter, r *http.Request) bool {
			w.Header().Set("Content-Type", "text/xml; charset=utf-8")
			flusher, _ := w.(http.Flusher)
			// No Content-Length: the cap has to hold on the read side too.
			for i := 0; i < 40; i++ {
				if _, err := w.Write([]byte(strings.Repeat("A", 8192))); err != nil {
					return true
				}
				if flusher != nil {
					flusher.Flush()
				}
			}
			return true
		}
		opts := server.options()
		opts.MaxResponseBytes = 4096

		r, err := NewArtifactResolver(opts)
		if err != nil {
			t.Fatalf("NewArtifactResolver: %v", err)
		}
		_, err = r.Resolve(context.Background(), mustArtifact(t).String())
		if !errors.Is(err, ErrTooLarge) {
			t.Fatalf("err = %v, want ErrTooLarge", err)
		}
	})

	t.Run("hung server hits the timeout", func(t *testing.T) {
		server := newArtifactIdP(t, idp, inner)
		// The release channel is closed *after* newArtifactIdP registered its
		// server.Close cleanup, so that cleanups running last-in-first-out
		// unblock the handler before the server waits for it.
		release := make(chan struct{})
		t.Cleanup(func() { close(release) })
		server.respond = func(w http.ResponseWriter, r *http.Request) bool {
			select {
			case <-release:
			case <-r.Context().Done():
			}
			return true
		}
		opts := server.options()
		opts.Timeout = 150 * time.Millisecond

		r, err := NewArtifactResolver(opts)
		if err != nil {
			t.Fatalf("NewArtifactResolver: %v", err)
		}
		start := time.Now()
		_, err = r.Resolve(context.Background(), mustArtifact(t).String())
		if err == nil {
			t.Fatal("a server that never answers produced no error")
		}
		if elapsed := time.Since(start); elapsed > 10*time.Second {
			t.Fatalf("the call took %v; the timeout was not applied", elapsed)
		}
	})

	t.Run("non-SOAP body", func(t *testing.T) {
		server := newArtifactIdP(t, idp, inner)
		server.respond = func(w http.ResponseWriter, r *http.Request) bool {
			_, _ = w.Write([]byte(`<html><body>login here</body></html>`))
			return true
		}
		r, err := NewArtifactResolver(server.options())
		if err != nil {
			t.Fatalf("NewArtifactResolver: %v", err)
		}
		if _, err := r.Resolve(context.Background(), mustArtifact(t).String()); err == nil {
			t.Fatal("an HTML body was accepted as a SOAP response")
		}
	})

	t.Run("HTTP error status", func(t *testing.T) {
		server := newArtifactIdP(t, idp, inner)
		server.respond = func(w http.ResponseWriter, r *http.Request) bool {
			http.Error(w, "no", http.StatusForbidden)
			return true
		}
		r, err := NewArtifactResolver(server.options())
		if err != nil {
			t.Fatalf("NewArtifactResolver: %v", err)
		}
		_, err = r.Resolve(context.Background(), mustArtifact(t).String())
		if err == nil || !strings.Contains(err.Error(), "403") {
			t.Fatalf("err = %v, want an error naming HTTP 403", err)
		}
	})

	t.Run("cancelled context", func(t *testing.T) {
		server := newArtifactIdP(t, idp, inner)
		r, err := NewArtifactResolver(server.options())
		if err != nil {
			t.Fatalf("NewArtifactResolver: %v", err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if _, err := r.Resolve(ctx, mustArtifact(t).String()); err == nil {
			t.Fatal("a cancelled context still produced a resolution")
		}
	})
}

// TestArtifactSingleUse: an artifact is a one-shot credential. Resolving the
// same one twice must fail, and must fail without touching the network.
func TestArtifactSingleUse(t *testing.T) {
	idp := newTestIdP(t, "rsa")
	f := newFixture(idp)
	f.signTarget = "response"
	server := newArtifactIdP(t, idp, f.xml(t))

	r, err := NewArtifactResolver(server.options())
	if err != nil {
		t.Fatalf("NewArtifactResolver: %v", err)
	}
	art := mustArtifact(t)
	if _, err := r.Resolve(context.Background(), art.String()); err != nil {
		t.Fatalf("first Resolve: %v", err)
	}
	_, err = r.Resolve(context.Background(), art.String())
	if !errors.Is(err, ErrReplay) {
		t.Fatalf("second Resolve: err = %v, want ErrReplay", err)
	}
	if server.calls != 1 {
		t.Errorf("resolution service called %d times, want 1", server.calls)
	}

	// The cache is the ordinary ReplayCache interface, so a caller can supply
	// a shared one; the resolver must not have invented a second mechanism.
	shared := NewMemoryReplayCache(0)
	opts := server.options()
	opts.ReplayCache = shared
	r2, err := NewArtifactResolver(opts)
	if err != nil {
		t.Fatalf("NewArtifactResolver: %v", err)
	}
	art2 := mustArtifact(t)
	if _, err := r2.Resolve(context.Background(), art2.String()); err != nil {
		t.Fatalf("Resolve with a shared cache: %v", err)
	}
	if shared.Len() != 1 {
		t.Errorf("shared cache holds %d entries, want 1", shared.Len())
	}
}

// TestArtifactResponseChecks covers the ArtifactResponse's own fields.
func TestArtifactResponseChecks(t *testing.T) {
	idp := newTestIdP(t, "rsa")
	f := newFixture(idp)
	f.signTarget = "response"
	inner := f.xml(t)

	t.Run("non-Success status", func(t *testing.T) {
		server := newArtifactIdP(t, idp, inner)
		server.status = StatusRequester
		server.innerXML = ""
		r, err := NewArtifactResolver(server.options())
		if err != nil {
			t.Fatalf("NewArtifactResolver: %v", err)
		}
		_, err = r.Resolve(context.Background(), mustArtifact(t).String())
		if !errors.Is(err, ErrArtifactStatus) {
			t.Fatalf("err = %v, want ErrArtifactStatus", err)
		}
	})

	t.Run("InResponseTo mismatch", func(t *testing.T) {
		server := newArtifactIdP(t, idp, inner)
		server.inResponseToOverride = "_someoneelsesrequest"
		r, err := NewArtifactResolver(server.options())
		if err != nil {
			t.Fatalf("NewArtifactResolver: %v", err)
		}
		_, err = r.Resolve(context.Background(), mustArtifact(t).String())
		if !errors.Is(err, ErrArtifactInResponseTo) {
			t.Fatalf("err = %v, want ErrArtifactInResponseTo", err)
		}
	})

	t.Run("foreign issuer", func(t *testing.T) {
		// The artifact's SourceID and the envelope's signature both check out;
		// only the stated issuer is somebody else. It must still be refused,
		// because "who signed this" and "who this claims to be from" have to
		// agree.
		server := newArtifactIdP(t, idp, inner)
		server.issuer = "https://evil.example.com/entity"
		r, err := NewArtifactResolver(server.options())
		if err != nil {
			t.Fatalf("NewArtifactResolver: %v", err)
		}
		_, err = r.Resolve(context.Background(), mustArtifact(t).String())
		if err == nil || !strings.Contains(err.Error(), "evil.example.com") {
			t.Fatalf("err = %v, want the foreign-issuer rejection", err)
		}
	})

	t.Run("no samlp:Response", func(t *testing.T) {
		server := newArtifactIdP(t, idp, "")
		r, err := NewArtifactResolver(server.options())
		if err != nil {
			t.Fatalf("NewArtifactResolver: %v", err)
		}
		if _, err := r.Resolve(context.Background(), mustArtifact(t).String()); err == nil {
			t.Fatal("an ArtifactResponse with no payload was accepted")
		}
	})

	t.Run("the endpoint never comes from the artifact", func(t *testing.T) {
		// The EndpointIndex is peer-controlled. Whatever it says, the call goes
		// to the configured URL; this is the SSRF property the binding lives or
		// dies by.
		server := newArtifactIdP(t, idp, inner)
		r, err := NewArtifactResolver(server.options())
		if err != nil {
			t.Fatalf("NewArtifactResolver: %v", err)
		}
		art, err := NewArtifact(testIssuer, 0xffff)
		if err != nil {
			t.Fatalf("NewArtifact: %v", err)
		}
		if _, err := r.Resolve(context.Background(), art.String()); err != nil {
			t.Fatalf("Resolve: %v", err)
		}
		if server.calls != 1 {
			t.Errorf("the configured endpoint was called %d times, want 1", server.calls)
		}
		if got := server.resolveRequests[0]; got == nil {
			t.Error("no ArtifactResolve reached the configured endpoint")
		}
	})

	t.Run("payload leaning on the envelope's namespaces", func(t *testing.T) {
		// A samlp:Response that only parses because the ArtifactResponse
		// declared its prefix cannot be lifted out without rewriting it, and
		// rewriting a document to check its signature is how the checked and
		// the acted-upon documents come to differ.
		bare := `<samlp:Response ID="_r9" Version="2.0" IssueInstant="` + iso(testNow) + `">` +
			`<samlp:Status><samlp:StatusCode Value="` + StatusSuccess + `"/></samlp:Status>` +
			`</samlp:Response>`
		server := newArtifactIdP(t, idp, bare)
		r, err := NewArtifactResolver(server.options())
		if err != nil {
			t.Fatalf("NewArtifactResolver: %v", err)
		}
		_, err = r.Resolve(context.Background(), mustArtifact(t).String())
		if err == nil || !strings.Contains(err.Error(), "declared outside") {
			t.Fatalf("err = %v, want the namespace self-containment refusal", err)
		}
	})
}

// TestArtifactResponseFields checks the metadata the resolver hands back
// alongside the payload.
func TestArtifactResponseFields(t *testing.T) {
	idp := newTestIdP(t, "rsa")
	f := newFixture(idp)
	f.signTarget = "response"
	server := newArtifactIdP(t, idp, f.xml(t))

	r, err := NewArtifactResolver(server.options())
	if err != nil {
		t.Fatalf("NewArtifactResolver: %v", err)
	}
	art := mustArtifact(t)
	res, err := r.Resolve(context.Background(), art.String())
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if !res.Signed || !res.InnerSigned {
		t.Errorf("Signed = %v, InnerSigned = %v, want both true", res.Signed, res.InnerSigned)
	}
	if res.Issuer != testIssuer {
		t.Errorf("Issuer = %q", res.Issuer)
	}
	if res.StatusCode != StatusSuccess {
		t.Errorf("StatusCode = %q", res.StatusCode)
	}
	if !res.IssueInstant.Equal(testNow) {
		t.Errorf("IssueInstant = %v", res.IssueInstant)
	}
	if res.Artifact == nil || res.Artifact.String() != art.String() {
		t.Error("the redeemed artifact was not carried back")
	}
	if !strings.HasPrefix(string(res.ResponseXML), "<samlp:Response") {
		t.Errorf("ResponseXML starts with %.40q", res.ResponseXML)
	}
	// The extraction must be signature preserving: the standalone document has
	// to validate on its own.
	if _, err := f.strategy().Validate(res.EncodedResponse()); err != nil {
		t.Fatalf("extracted response does not validate: %v", err)
	}
}

// TestArtifactExtractionPreservesAssertionSignature repeats the extraction check
// for an assertion-level signature, where exclusive canonicalization has to
// reproduce the assertion's bytes from inside two extra layers of envelope.
func TestArtifactExtractionPreservesAssertionSignature(t *testing.T) {
	idp := newTestIdP(t, "rsa")
	for _, c14n := range []string{AlgC14NExclusive, AlgC14N} {
		t.Run(c14n, func(t *testing.T) {
			f := newFixture(idp)
			f.signTarget = "assertion"
			f.c14nAlg = c14n
			f.transforms = []string{AlgEnvelopedSignature, c14n}
			server := newArtifactIdP(t, idp, f.xml(t))

			r, err := NewArtifactResolver(server.options())
			if err != nil {
				t.Fatalf("NewArtifactResolver: %v", err)
			}
			a, err := r.ResolveAssertion(context.Background(), mustArtifact(t).String(), f.strategy())
			if err != nil {
				t.Fatalf("ResolveAssertion: %v", err)
			}
			if a.NameID != testNameID {
				t.Errorf("NameID = %q", a.NameID)
			}
		})
	}
}

// TestArtifactResolverConfiguration covers the fail-fast configuration checks,
// including the two that exist purely to keep the back channel from becoming an
// attack surface.
func TestArtifactResolverConfiguration(t *testing.T) {
	base := func() ArtifactOptions {
		return ArtifactOptions{
			EntityID:              testArtifactSPEntityID,
			IdPEntityID:           testIssuer,
			ArtifactResolutionURL: "https://idp.example.com/ars",
		}
	}

	for _, tc := range []struct {
		name string
		mut  func(*ArtifactOptions)
	}{
		{"no EntityID", func(o *ArtifactOptions) { o.EntityID = "" }},
		{"no IdPEntityID", func(o *ArtifactOptions) { o.IdPEntityID = "" }},
		{"no resolution URL", func(o *ArtifactOptions) { o.ArtifactResolutionURL = "" }},
		{"SHA-1 signing algorithm", func(o *ArtifactOptions) {
			o.SignatureAlgorithm = "http://www.w3.org/2000/09/xmldsig#rsa-sha1"
		}},
		{"unparsable certificate PEM", func(o *ArtifactOptions) {
			o.IdPCertificatePEM = []byte("-----BEGIN CERTIFICATE-----\nnope\n-----END CERTIFICATE-----\n")
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			opts := base()
			tc.mut(&opts)
			if _, err := NewArtifactResolver(opts); err == nil {
				t.Fatal("bad configuration was accepted")
			}
		})
	}

	t.Run("TLS verification may not be disabled", func(t *testing.T) {
		opts := base()
		opts.HTTPClient = &http.Client{
			Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
		}
		_, err := NewArtifactResolver(opts)
		if !errors.Is(err, ErrInsecureTLS) {
			t.Fatalf("err = %v, want ErrInsecureTLS", err)
		}
	})

	t.Run("a supplied client is not mutated", func(t *testing.T) {
		opts := base()
		client := &http.Client{}
		opts.HTTPClient = client
		if _, err := NewArtifactResolver(opts); err != nil {
			t.Fatalf("NewArtifactResolver: %v", err)
		}
		if client.Timeout != 0 || client.CheckRedirect != nil {
			t.Error("the caller's http.Client was modified in place")
		}
	})

	t.Run("a default timeout is always applied", func(t *testing.T) {
		opts := base()
		r, err := NewArtifactResolver(opts)
		if err != nil {
			t.Fatalf("NewArtifactResolver: %v", err)
		}
		if r.soap.client.Timeout <= 0 {
			t.Fatal("the back-channel client has no timeout")
		}
		if r.soap.client.Timeout != DefaultSOAPTimeout {
			t.Errorf("Timeout = %v, want %v", r.soap.client.Timeout, DefaultSOAPTimeout)
		}
	})
}

// TestArtifactRedirectPolicy: following a redirect to another host would hand
// the destination of the back-channel call back to the peer, which is exactly
// the server-side request forgery the configured endpoint rule exists to
// prevent.
func TestArtifactRedirectPolicy(t *testing.T) {
	idp := newTestIdP(t, "rsa")
	f := newFixture(idp)
	f.signTarget = "response"

	elsewhere := newArtifactIdP(t, idp, f.xml(t))
	front := newArtifactIdP(t, idp, f.xml(t))
	front.respond = func(w http.ResponseWriter, r *http.Request) bool {
		http.Redirect(w, r, elsewhere.URL, http.StatusTemporaryRedirect)
		return true
	}

	r, err := NewArtifactResolver(front.options())
	if err != nil {
		t.Fatalf("NewArtifactResolver: %v", err)
	}
	_, err = r.Resolve(context.Background(), mustArtifact(t).String())
	if err == nil {
		t.Fatal("a cross-host redirect was followed")
	}
	if !strings.Contains(err.Error(), "different host") {
		t.Fatalf("err = %v, want the cross-host refusal", err)
	}
	if elsewhere.calls != 0 {
		t.Errorf("the redirect target was called %d times", elsewhere.calls)
	}
}

// TestBackChannelRedirectRules pins the redirect policy directly, including the
// same-host cases it has to keep allowing.
func TestBackChannelRedirectRules(t *testing.T) {
	req := func(url string) *http.Request {
		r, err := http.NewRequest(http.MethodGet, url, nil)
		if err != nil {
			t.Fatalf("NewRequest(%q): %v", url, err)
		}
		return r
	}
	for _, tc := range []struct {
		name     string
		from, to string
		via      int
		wantErr  bool
	}{
		{"same host", "https://idp.example.com/a", "https://idp.example.com/b", 1, false},
		{"different host", "https://idp.example.com/a", "https://evil.example.com/b", 1, true},
		{"different port is a different host", "https://idp.example.com/a", "https://idp.example.com:8443/b", 1, true},
		{"scheme downgrade", "https://idp.example.com/a", "http://idp.example.com/b", 1, true},
		{"scheme upgrade is fine", "http://idp.example.com/a", "https://idp.example.com/b", 1, false},
		{"too many redirects", "https://idp.example.com/a", "https://idp.example.com/b", maxSOAPRedirects, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			via := make([]*http.Request, tc.via)
			for i := range via {
				via[i] = req(tc.from)
			}
			err := checkBackChannelRedirect(req(tc.to), via)
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, wantErr = %v", err, tc.wantErr)
			}
		})
	}
}

// TestNewArtifactIsUnpredictable: the MessageHandle is the only thing standing
// between a stranger and somebody else's assertion, so it must come from
// crypto/rand and never repeat.
func TestNewArtifactIsUnpredictable(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 64; i++ {
		a, err := NewArtifact(testIssuer, 0)
		if err != nil {
			t.Fatalf("NewArtifact: %v", err)
		}
		if len(a.Raw) != ArtifactLength {
			t.Fatalf("Raw is %d octets", len(a.Raw))
		}
		key := fmt.Sprintf("%x", a.MessageHandle)
		if seen[key] {
			t.Fatalf("MessageHandle %s repeated after %d artifacts", key, i)
		}
		seen[key] = true
		if a.MessageHandle == ([20]byte{}) {
			t.Fatal("MessageHandle is all zeroes")
		}
	}
}

// TestSourceIDFor pins the SourceID construction against the specification: the
// SHA-1 of the entity ID's UTF-8 octets. The expected value below is the SHA-1
// of the ASCII string, computed with the standard library rather than copied
// from anywhere.
func TestSourceIDFor(t *testing.T) {
	got := SourceIDFor(testIssuer)
	want := sha1.Sum([]byte(testIssuer))
	if got != want {
		t.Errorf("SourceIDFor = %x, want %x", got, want)
	}
	if SourceIDFor("") == SourceIDFor(testIssuer) {
		t.Error("distinct entity IDs produced the same SourceID")
	}
}

// TestSOAPEnvelopeRoundTrip checks the envelope this package writes is the one
// it can read back, and that a fault or a malformed body is an error.
func TestSOAPEnvelopeRoundTrip(t *testing.T) {
	env := soapEnvelope(`<samlp:ArtifactResolve xmlns:samlp="` + nsSAMLProtocol + `" ID="_x"/>`)
	elem, err := parseSOAPBody(env, defaultMaxDepth)
	if err != nil {
		t.Fatalf("parseSOAPBody: %v", err)
	}
	if !elem.is(nsSAMLProtocol, "ArtifactResolve") {
		t.Errorf("body carried <%s>", elem.local)
	}

	for _, tc := range []struct {
		name string
		body string
	}{
		{"not an envelope", `<html/>`},
		{"two elements in the body", `<?xml version="1.0"?><soap:Envelope xmlns:soap="` + nsSOAP11 +
			`"><soap:Body><a xmlns=""/><b xmlns=""/></soap:Body></soap:Envelope>`},
		{"empty body", `<?xml version="1.0"?><soap:Envelope xmlns:soap="` + nsSOAP11 +
			`"><soap:Body></soap:Body></soap:Envelope>`},
		{"no body", `<?xml version="1.0"?><soap:Envelope xmlns:soap="` + nsSOAP11 + `"/>`},
		{"DOCTYPE", `<!DOCTYPE x><soap:Envelope xmlns:soap="` + nsSOAP11 + `"/>`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := parseSOAPBody([]byte(tc.body), defaultMaxDepth); err == nil {
				t.Fatal("malformed SOAP was accepted")
			}
		})
	}
}

// --- xs:duration -----------------------------------------------------------

// TestParseXSDuration is the table of lexical forms. Every expected value is
// derived from the ISO 8601 / XML Schema grammar directly: PnYnMnDTnHnMnS, with
// M meaning months before the T and minutes after it.
//
// Against the pre-change package none of this compiles: cacheDuration was kept
// as an unparsed string and there was no XSDuration.
func TestParseXSDuration(t *testing.T) {
	for _, tc := range []struct {
		in    string
		neg   bool
		y     int
		mo    int
		d     int
		fixed time.Duration
	}{
		{in: "P1Y2M3DT4H5M6S", y: 1, mo: 2, d: 3, fixed: 4*time.Hour + 5*time.Minute + 6*time.Second},
		{in: "-P1Y2M3DT4H5M6S", neg: true, y: 1, mo: 2, d: 3, fixed: 4*time.Hour + 5*time.Minute + 6*time.Second},
		// The classic bug: P1M is one month, PT1M is one minute.
		{in: "P1M", mo: 1},
		{in: "PT1M", fixed: time.Minute},
		{in: "P1Y", y: 1},
		{in: "P1D", d: 1},
		{in: "PT1H", fixed: time.Hour},
		{in: "PT1S", fixed: time.Second},
		{in: "P0D"},
		{in: "PT0S"},
		// Fractional seconds, and only seconds.
		{in: "PT0.5S", fixed: 500 * time.Millisecond},
		{in: "PT1.5S", fixed: 1500 * time.Millisecond},
		{in: "PT.5S", fixed: 500 * time.Millisecond},
		{in: "PT1.000000001S", fixed: time.Second + time.Nanosecond},
		// Beyond nanosecond resolution the excess is truncated, not rounded up
		// into a duration that was never written.
		{in: "PT0.0000000004S", fixed: 0},
		{in: "-PT0.25S", neg: true, fixed: 250 * time.Millisecond},
		{in: "P10Y", y: 10},
		{in: "PT36H", fixed: 36 * time.Hour},
		{in: "P1DT23H59M59S", d: 1, fixed: 23*time.Hour + 59*time.Minute + 59*time.Second},
	} {
		t.Run(tc.in, func(t *testing.T) {
			got, err := ParseXSDuration(tc.in)
			if err != nil {
				t.Fatalf("ParseXSDuration(%q): %v", tc.in, err)
			}
			if got.Negative != tc.neg || got.Years != tc.y || got.Months != tc.mo ||
				got.Days != tc.d || got.Fixed != tc.fixed {
				t.Errorf("= %+v, want neg=%v y=%d mo=%d d=%d fixed=%v",
					got, tc.neg, tc.y, tc.mo, tc.d, tc.fixed)
			}
			if got.Raw != tc.in {
				t.Errorf("Raw = %q, want %q", got.Raw, tc.in)
			}
			if got.String() != tc.in {
				t.Errorf("String() = %q, does not round-trip %q", got.String(), tc.in)
			}
			if !got.Present() {
				t.Error("Present() = false for a parsed duration")
			}
			// xs:duration is a whiteSpace="collapse" schema type, so an
			// attribute value padded by the document's formatting parses.
			if padded, err := ParseXSDuration(" " + tc.in + "\n"); err != nil {
				t.Errorf("surrounding whitespace was rejected: %v", err)
			} else if padded.Fixed != tc.fixed || padded.Months != tc.mo {
				t.Errorf("padded = %+v", padded)
			}
		})
	}
}

// TestParseXSDurationRejects covers the forms the grammar forbids. A bare "P"
// and a trailing "T" are the two the specification calls out explicitly.
func TestParseXSDurationRejects(t *testing.T) {
	for _, in := range []string{
		"",
		" ",
		"P",      // at least one component is required
		"-P",     //
		"PT",     // T with nothing after it
		"P1YT",   // ditto, with a date part present
		"1Y",     // no P
		"P1H",    // hours belong after the T
		"PT1D",   // days belong before the T
		"P1S",    // seconds belong after the T
		"P1M1Y",  // out of order
		"P1Y1Y",  // repeated
		"PT1M1H", // out of order in the time part
		"P1.5Y",  // only seconds may be fractional
		"PT1.5H", //
		"PT1.5M", //
		"P-1Y",   // the sign goes at the front, once
		"+P1Y",   //
		"P1YX",   // trailing rubbish
		"PT1.2.3S",
		"PT.S",
		"P99999999999Y", // out of range
		"PT99999999999H",
		"PYM",
		"PTS",
	} {
		t.Run(in, func(t *testing.T) {
			got, err := ParseXSDuration(in)
			if err == nil {
				t.Fatalf("ParseXSDuration(%q) = %+v, want an error", in, got)
			}
			if !errors.Is(err, ErrMalformedDuration) {
				t.Errorf("err = %v, want ErrMalformedDuration", err)
			}
			if got != (XSDuration{}) {
				t.Errorf("a failed parse returned %+v, want the zero value", got)
			}
		})
	}
}

// TestXSDurationAddTo is the calendar behaviour: months are not a fixed number
// of seconds, and AddTo is the only method that gets that right.
func TestXSDurationAddTo(t *testing.T) {
	for _, tc := range []struct {
		name string
		dur  string
		from time.Time
		want time.Time
	}{
		{
			// January has 31 days: P1M from 1 January lands on 1 February.
			name: "one month from a 31-day month",
			dur:  "P1M",
			from: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
			want: time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC),
		},
		{
			// One minute, for contrast, from the identical instant.
			name: "one minute",
			dur:  "PT1M",
			from: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
			want: time.Date(2026, 1, 1, 0, 1, 0, 0, time.UTC),
		},
		{
			// AddDate normalizes 31 February to 3 March in a leap year:
			// February 2024 has 29 days, so 31 - 29 = 2 days over.
			name: "month-end normalization",
			dur:  "P1M",
			from: time.Date(2024, 1, 31, 0, 0, 0, 0, time.UTC),
			want: time.Date(2024, 3, 2, 0, 0, 0, 0, time.UTC),
		},
		{
			// A leap year: 2024-02-29 plus a year normalizes to 2025-03-01.
			name: "leap day plus a year",
			dur:  "P1Y",
			from: time.Date(2024, 2, 29, 0, 0, 0, 0, time.UTC),
			want: time.Date(2025, 3, 1, 0, 0, 0, 0, time.UTC),
		},
		{
			name: "full duration",
			dur:  "P1Y2M3DT4H5M6S",
			from: time.Date(2026, 1, 2, 15, 4, 5, 0, time.UTC),
			want: time.Date(2027, 3, 5, 19, 9, 11, 0, time.UTC),
		},
		{
			name: "negative runs backwards",
			dur:  "-P1Y2M3DT4H5M6S",
			from: time.Date(2027, 3, 5, 19, 9, 11, 0, time.UTC),
			want: time.Date(2026, 1, 2, 15, 4, 5, 0, time.UTC),
		},
		{
			name: "fractional seconds",
			dur:  "PT0.25S",
			from: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
			want: time.Date(2026, 1, 1, 0, 0, 0, 250_000_000, time.UTC),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d, err := ParseXSDuration(tc.dur)
			if err != nil {
				t.Fatalf("ParseXSDuration(%q): %v", tc.dur, err)
			}
			if got := d.AddTo(tc.from); !got.Equal(tc.want) {
				t.Errorf("%q.AddTo(%s) = %s, want %s", tc.dur,
					tc.from.Format(time.RFC3339Nano), got.Format(time.RFC3339Nano),
					tc.want.Format(time.RFC3339Nano))
			}
		})
	}
}

// TestXSDurationApproximateDuration pins the documented convention: a year is
// 365.2425 days (31556952 s) and a month a twelfth of that (2629746 s). Both
// constants are exact, so the expectations below are exact too.
func TestXSDurationApproximateDuration(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want time.Duration
	}{
		{"PT1H", time.Hour},
		{"P1D", 24 * time.Hour},
		{"P1M", 2629746 * time.Second},
		{"P1Y", 31556952 * time.Second},
		{"P12M", 12 * 2629746 * time.Second}, // equals P1Y by construction
		{"-P1D", -24 * time.Hour},
		{"P1DT1H", 25 * time.Hour},
	} {
		t.Run(tc.in, func(t *testing.T) {
			d, err := ParseXSDuration(tc.in)
			if err != nil {
				t.Fatalf("ParseXSDuration: %v", err)
			}
			if got := d.ApproximateDuration(); got != tc.want {
				t.Errorf("= %v, want %v", got, tc.want)
			}
		})
	}
	// The twelve-month and one-year approximations agree exactly, which is the
	// property that makes the pair of constants defensible.
	y, _ := ParseXSDuration("P1Y")
	m, _ := ParseXSDuration("P12M")
	if y.ApproximateDuration() != m.ApproximateDuration() {
		t.Errorf("P1Y = %v but P12M = %v", y.ApproximateDuration(), m.ApproximateDuration())
	}
}

// TestXSDurationZeroValue documents what an absent attribute looks like.
func TestXSDurationZeroValue(t *testing.T) {
	var d XSDuration
	if d.Present() {
		t.Error("the zero value reports Present()")
	}
	if !d.IsZero() {
		t.Error("the zero value is not IsZero()")
	}
	if got := d.String(); got != "P0D" {
		t.Errorf("String() = %q, want the canonical zero %q", got, "P0D")
	}
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	if got := d.AddTo(now); !got.Equal(now) {
		t.Errorf("the zero duration moved %s to %s", now, got)
	}
	// A hand-built value with no Raw renders canonically.
	built := XSDuration{Years: 1, Months: 2, Fixed: 90 * time.Minute}
	if got := built.String(); got != "P1Y2MT1H30M" {
		t.Errorf("String() = %q, want %q", got, "P1Y2MT1H30M")
	}
	if built.IsZero() {
		t.Error("a non-empty duration reports IsZero()")
	}
}

// --- metadata integration --------------------------------------------------

// TestMetadataArtifactResolution reads md:ArtifactResolutionService endpoints
// and configures a resolver from them, which is the supported way to obtain the
// endpoint without hard-coding it.
func TestMetadataArtifactResolution(t *testing.T) {
	idp := newTestIdP(t, "rsa")
	const ars0 = "https://idp.example.com/ars/0"
	const ars1 = "https://idp.example.com/ars/1"

	doc := `<md:EntityDescriptor xmlns:md="` + nsMetadata + `" xmlns:ds="` + nsDSig + `"` +
		` entityID="` + testIssuer + `" cacheDuration="P1DT12H">` +
		`<md:IDPSSODescriptor protocolSupportEnumeration="` + nsSAMLProtocol + `">` +
		`<md:KeyDescriptor use="signing"><ds:KeyInfo><ds:X509Data><ds:X509Certificate>` +
		base64.StdEncoding.EncodeToString(idp.cert.Raw) +
		`</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>` +
		`<md:ArtifactResolutionService Binding="` + BindingSOAP + `" Location="` + ars0 + `" index="0"/>` +
		`<md:ArtifactResolutionService Binding="` + BindingSOAP + `" Location="` + ars1 + `" index="1" isDefault="true"/>` +
		`<md:SingleSignOnService Binding="` + BindingHTTPRedirect + `" Location="` + testIdPSSOURL + `"/>` +
		`</md:IDPSSODescriptor></md:EntityDescriptor>`

	m, err := ParseIdPMetadata([]byte(doc), MetadataOptions{Now: testClock})
	if err != nil {
		t.Fatalf("ParseIdPMetadata: %v", err)
	}
	if len(m.ArtifactResolutionServices) != 2 {
		t.Fatalf("ArtifactResolutionServices = %+v", m.ArtifactResolutionServices)
	}
	if got := m.ArtifactResolutionURL(0); got != ars0 {
		t.Errorf("ArtifactResolutionURL(0) = %q", got)
	}
	if got := m.ArtifactResolutionURL(1); got != ars1 {
		t.Errorf("ArtifactResolutionURL(1) = %q", got)
	}
	if got := m.ArtifactResolutionURL(-1); got != ars1 {
		t.Errorf("ArtifactResolutionURL(default) = %q, want the isDefault endpoint %q", got, ars1)
	}
	if got := m.ArtifactResolutionURL(7); got != "" {
		t.Errorf("ArtifactResolutionURL(7) = %q, want empty", got)
	}
	if m.CacheDuration.Days != 1 || m.CacheDuration.Fixed != 12*time.Hour {
		t.Errorf("CacheDuration = %+v", m.CacheDuration)
	}

	opts := ArtifactOptions{EntityID: testArtifactSPEntityID}
	if err := m.ApplyToArtifactOptions(&opts, -1); err != nil {
		t.Fatalf("ApplyToArtifactOptions: %v", err)
	}
	if opts.ArtifactResolutionURL != ars1 || opts.IdPEntityID != testIssuer ||
		len(opts.IdPCertificates) != 1 {
		t.Errorf("options = %+v", opts)
	}
	if _, err := NewArtifactResolver(opts); err != nil {
		t.Fatalf("metadata-derived options were rejected: %v", err)
	}
	if err := m.ApplyToArtifactOptions(&opts, 9); err == nil {
		t.Error("a missing endpoint index was accepted")
	}
	if err := m.ApplyToArtifactOptions(nil, 0); err == nil {
		t.Error("nil ArtifactOptions was accepted")
	}
}

// TestMetadataRejectsMalformedCacheDuration: a malformed duration in a remote
// document must be an error, not a silent zero that would quietly turn caching
// off.
func TestMetadataRejectsMalformedCacheDuration(t *testing.T) {
	idp := newTestIdP(t, "rsa")
	doc := `<md:EntityDescriptor xmlns:md="` + nsMetadata + `" xmlns:ds="` + nsDSig + `"` +
		` entityID="` + testIssuer + `" cacheDuration="1H">` +
		`<md:IDPSSODescriptor protocolSupportEnumeration="` + nsSAMLProtocol + `">` +
		`<md:KeyDescriptor use="signing"><ds:KeyInfo><ds:X509Data><ds:X509Certificate>` +
		base64.StdEncoding.EncodeToString(idp.cert.Raw) +
		`</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>` +
		`<md:SingleSignOnService Binding="` + BindingHTTPRedirect + `" Location="` + testIdPSSOURL + `"/>` +
		`</md:IDPSSODescriptor></md:EntityDescriptor>`

	_, err := ParseIdPMetadata([]byte(doc), MetadataOptions{Now: testClock})
	if !errors.Is(err, ErrMalformedDuration) {
		t.Fatalf("err = %v, want ErrMalformedDuration", err)
	}
}

// ExampleParseXSDuration shows the month-versus-minute distinction that makes
// xs:duration worth a type of its own.
func ExampleParseXSDuration() {
	start := time.Date(2026, 1, 31, 12, 0, 0, 0, time.UTC)

	month, err := ParseXSDuration("P1M")
	if err != nil {
		panic(err)
	}
	minute, err := ParseXSDuration("PT1M")
	if err != nil {
		panic(err)
	}

	fmt.Println("P1M  ->", month.AddTo(start).Format(time.RFC3339))
	fmt.Println("PT1M ->", minute.AddTo(start).Format(time.RFC3339))
	fmt.Println("P1M as an approximation:", month.ApproximateDuration())
	// Output:
	// P1M  -> 2026-03-03T12:00:00Z
	// PT1M -> 2026-01-31T12:01:00Z
	// P1M as an approximation: 730h29m6s
}

// ExampleParseArtifact decodes the SAMLart parameter and checks that it was
// issued by the identity provider this service provider is configured for.
func ExampleParseArtifact() {
	const idpEntityID = "https://idp.example.com/entity"

	// The identity provider's side, shown here only to produce a value to
	// parse. A real service provider receives this in a query parameter.
	issued, err := NewArtifact(idpEntityID, 0)
	if err != nil {
		panic(err)
	}

	art, err := ParseArtifact(issued.String())
	if err != nil {
		panic(err)
	}
	fmt.Printf("type 0x%04x, endpoint %d\n", art.TypeCode, art.EndpointIndex)
	fmt.Println("issued by the configured IdP:", art.CheckSourceID(idpEntityID) == nil)
	fmt.Println("issued by someone else:", art.CheckSourceID("https://evil.example.com") == nil)
	// Output:
	// type 0x0004, endpoint 0
	// issued by the configured IdP: true
	// issued by someone else: false
}
