package saml

import (
	"crypto/x509"
	"encoding/base64"
	"errors"
	"net/url"
	"strings"
	"testing"
	"time"
)

// This file covers the protocol surface added alongside the ACS strategy:
// AuthnRequest construction and both of its bindings, single logout, and IdP
// metadata parsing. Like the rest of the suite it is self-contained: keys are
// generated in-process, the clock is injected and message IDs come from a
// deterministic generator, so nothing here depends on wall-clock time.

const (
	testSPEntityID = "https://sp.example.com/metadata"
	testIdPSSOURL  = "https://idp.example.com/sso"
	testIdPSLOURL  = "https://idp.example.com/slo"
	testSPSLOURL   = "https://sp.example.com/slo"
)

// seqIDs returns a deterministic ID generator, so a test can assert on the
// exact ID a message carries.
func seqIDs(ids ...string) func() (string, error) {
	i := 0
	return func() (string, error) {
		if i >= len(ids) {
			return "", errors.New("test: ran out of IDs")
		}
		id := ids[i]
		i++
		return id, nil
	}
}

func testClock() time.Time { return testNow }

// --- HTTP-Redirect binding -------------------------------------------------

// TestRedirectSignedStringKnownAnswer pins the exact octet string the
// HTTP-Redirect binding signs.
//
// Derivation, from SAML 2.0 Bindings (OASIS, saml-bindings-2.0-os) §3.4.4.1:
// the signature is computed over the concatenation
//
//	SAMLRequest=value&RelayState=value&SigAlg=value
//
// in that order, with RelayState present if and only if the parameter is
// present, each value URL-encoded as an application/x-www-form-urlencoded
// component, and no other parameter (in particular not Signature) included.
//
// Applying that encoding by hand to the inputs below — unreserved characters
// are A-Z a-z 0-9 - _ . ~ ; a space becomes '+' ; anything else becomes %XX
// with uppercase hex:
//
//	"abc+/="  -> 'a','b','c' literal, '+'=0x2B -> %2B, '/'=0x2F -> %2F,
//	             '='=0x3D -> %3D                       => abc%2B%2F%3D
//	"a b&c"   -> 'a', ' ' -> '+', 'b', '&'=0x26 -> %26, 'c'
//	                                                    => a+b%26c
//	the SigAlg URI -> ':'=0x3A -> %3A, each '/' -> %2F, '#'=0x23 -> %23,
//	             '.' and '-' are unreserved and survive
//	          => http%3A%2F%2Fwww.w3.org%2F2001%2F04%2Fxmldsig-more%23rsa-sha256
func TestRedirectSignedStringKnownAnswer(t *testing.T) {
	const (
		msg   = "abc+/="
		relay = "a b&c"
	)
	got := redirectSignedString("SAMLRequest",
		url.QueryEscape(msg), true, url.QueryEscape(relay), url.QueryEscape(SigAlgRSASHA256))
	want := "SAMLRequest=abc%2B%2F%3D" +
		"&RelayState=a+b%26c" +
		"&SigAlg=http%3A%2F%2Fwww.w3.org%2F2001%2F04%2Fxmldsig-more%23rsa-sha256"
	if got != want {
		t.Errorf("signed string:\n got %s\nwant %s", got, want)
	}

	// With no RelayState the parameter is omitted entirely, not sent empty.
	got = redirectSignedString("SAMLResponse", url.QueryEscape(msg), false, "", url.QueryEscape(SigAlgRSASHA256))
	want = "SAMLResponse=abc%2B%2F%3D" +
		"&SigAlg=http%3A%2F%2Fwww.w3.org%2F2001%2F04%2Fxmldsig-more%23rsa-sha256"
	if got != want {
		t.Errorf("signed string without RelayState:\n got %s\nwant %s", got, want)
	}
}

func TestDeflateRoundTrip(t *testing.T) {
	for _, in := range []string{
		"",
		"<samlp:AuthnRequest/>",
		strings.Repeat("<a>value &amp; more</a>", 500),
	} {
		enc, err := DeflateEncode([]byte(in))
		if err != nil {
			t.Fatalf("DeflateEncode: %v", err)
		}
		if _, err := base64.StdEncoding.DecodeString(enc); err != nil {
			t.Fatalf("DeflateEncode did not produce standard base64: %v", err)
		}
		out, err := DeflateDecode(enc, defaultMaxResponseBytes)
		if err != nil {
			t.Fatalf("DeflateDecode: %v", err)
		}
		if string(out) != in {
			t.Errorf("round trip changed the message (%d bytes in, %d out)", len(in), len(out))
		}
	}
}

// TestDeflateDecodeBounded checks that the inflate cap is enforced, since a
// short query string can otherwise inflate without bound.
func TestDeflateDecodeBounded(t *testing.T) {
	enc, err := DeflateEncode([]byte(strings.Repeat("A", 1<<20)))
	if err != nil {
		t.Fatalf("DeflateEncode: %v", err)
	}
	if len(enc) > 4096 {
		t.Fatalf("test premise broken: compressed to %d bytes", len(enc))
	}
	if _, err := DeflateDecode(enc, 1024); !errors.Is(err, ErrTooLarge) {
		t.Errorf("DeflateDecode over the cap: got %v, want ErrTooLarge", err)
	}
}

func TestDeflateDecodeRejectsZlibHeader(t *testing.T) {
	// A zlib stream (RFC 1950) is a two-byte header plus the raw DEFLATE data
	// the binding actually specifies. Feeding one to a raw inflater must fail
	// rather than silently produce garbage.
	raw, err := DeflateEncode([]byte("<samlp:AuthnRequest/>"))
	if err != nil {
		t.Fatalf("DeflateEncode: %v", err)
	}
	rawBytes, _ := base64.StdEncoding.DecodeString(raw)
	zlib := append([]byte{0x78, 0x9c}, rawBytes...)
	if _, err := DeflateDecode(base64.StdEncoding.EncodeToString(zlib), 0); err == nil {
		t.Error("a zlib-wrapped stream was accepted by the raw DEFLATE decoder")
	}
}

// newTestBuilder returns a request builder signing with idp's key. The key is
// standing in for the SP's own key; only the key pair matters.
func newTestBuilder(t *testing.T, idp *testIdP, mutate ...func(*RequestOptions)) *RequestBuilder {
	t.Helper()
	opts := RequestOptions{
		EntityID:                    testSPEntityID,
		SSOServiceURL:               testIdPSSOURL,
		AssertionConsumerServiceURL: testACS,
		SigningKey:                  idp.key,
		SigningCertificate:          idp.cert,
		Clock:                       testClock,
		NewID:                       seqIDs("_req1", "_req2", "_req3"),
	}
	for _, m := range mutate {
		m(&opts)
	}
	b, err := NewRequestBuilder(opts)
	if err != nil {
		t.Fatalf("NewRequestBuilder: %v", err)
	}
	return b
}

func TestAuthnRequestContents(t *testing.T) {
	idp := newTestIdP(t, "rsa")
	b := newTestBuilder(t, idp, func(o *RequestOptions) {
		o.NameIDFormat = NameIDFormatEmailAddress
		o.AllowCreate = true
		o.ForceAuthn = true
		o.IsPassive = true
		o.ProviderName = "Example SP"
		o.AuthnContextClassRefs = []string{"urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"}
	})
	req, err := b.BuildAuthnRequest()
	if err != nil {
		t.Fatalf("BuildAuthnRequest: %v", err)
	}
	if req.ID != "_req1" {
		t.Errorf("ID = %q, want _req1", req.ID)
	}
	if !req.IssueInstant.Equal(testNow) {
		t.Errorf("IssueInstant = %v, want %v", req.IssueInstant, testNow)
	}
	doc := string(req.XML)
	for _, want := range []string{
		`ID="_req1"`,
		`Version="2.0"`,
		`IssueInstant="2026-01-02T15:04:05Z"`,
		`Destination="` + testIdPSSOURL + `"`,
		`AssertionConsumerServiceURL="` + testACS + `"`,
		`ProtocolBinding="` + BindingHTTPPost + `"`,
		`ForceAuthn="true"`,
		`IsPassive="true"`,
		`ProviderName="Example SP"`,
		`<saml:Issuer>` + testSPEntityID + `</saml:Issuer>`,
		`<samlp:NameIDPolicy Format="` + NameIDFormatEmailAddress + `" AllowCreate="true"/>`,
		`<samlp:RequestedAuthnContext Comparison="exact">`,
	} {
		if !strings.Contains(doc, want) {
			t.Errorf("AuthnRequest is missing %s\n%s", want, doc)
		}
	}
	// The unsigned form must not contain the placeholder.
	if strings.Contains(doc, signatureMarker) {
		t.Error("AuthnRequest.XML still contains the signature placeholder")
	}
	// It must parse under the hardened parser.
	root, err := parseXML(req.XML, defaultMaxDepth)
	if err != nil {
		t.Fatalf("parsing the request we built: %v", err)
	}
	if !root.is(nsSAMLProtocol, "AuthnRequest") {
		t.Errorf("root element is <%s>", root.local)
	}
}

// TestAuthnRequestIDIsUnpredictable checks the default ID source. A counter or
// a timestamp here would let an attacker guess the InResponseTo value a
// response needs to carry.
func TestAuthnRequestIDIsUnpredictable(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 100; i++ {
		id, err := NewMessageID()
		if err != nil {
			t.Fatalf("NewMessageID: %v", err)
		}
		if !strings.HasPrefix(id, "_") || len(id) != 33 {
			t.Fatalf("NewMessageID returned %q, want _ plus 32 hex characters", id)
		}
		if seen[id] {
			t.Fatalf("NewMessageID repeated %q", id)
		}
		seen[id] = true
	}
}

func TestRedirectBindingSignedAndVerified(t *testing.T) {
	idp := newTestIdP(t, "rsa")
	b := newTestBuilder(t, idp)
	req, err := b.BuildAuthnRequest()
	if err != nil {
		t.Fatalf("BuildAuthnRequest: %v", err)
	}
	raw, err := b.RedirectURL(req, "return-to-dashboard")
	if err != nil {
		t.Fatalf("RedirectURL: %v", err)
	}
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parsing redirect URL: %v", err)
	}
	if got := u.Scheme + "://" + u.Host + u.Path; got != testIdPSSOURL {
		t.Errorf("redirect points at %q, want %q", got, testIdPSSOURL)
	}
	// Parameter order in the query string is normative for the signature.
	if !strings.HasPrefix(u.RawQuery, "SAMLRequest=") {
		t.Errorf("query does not start with SAMLRequest: %s", u.RawQuery)
	}
	for _, name := range []string{"RelayState=", "SigAlg=", "Signature="} {
		if !strings.Contains(u.RawQuery, name) {
			t.Errorf("query is missing %s: %s", name, u.RawQuery)
		}
	}

	msg, err := parseRedirect(u.RawQuery, "SAMLRequest",
		[]*x509.Certificate{idp.cert}, false, true, defaultMaxResponseBytes)
	if err != nil {
		t.Fatalf("verifying our own redirect signature: %v", err)
	}
	if !msg.signed {
		t.Error("message was not reported as signed")
	}
	if msg.relayState != "return-to-dashboard" {
		t.Errorf("RelayState = %q", msg.relayState)
	}
	if string(msg.xml) != string(req.XML) {
		t.Error("the inflated message differs from the one we built")
	}
}

func TestRedirectBindingTamperedParameters(t *testing.T) {
	idp := newTestIdP(t, "rsa")
	b := newTestBuilder(t, idp)
	req, err := b.BuildAuthnRequest()
	if err != nil {
		t.Fatalf("BuildAuthnRequest: %v", err)
	}
	raw, err := b.RedirectURL(req, "a b")
	if err != nil {
		t.Fatalf("RedirectURL: %v", err)
	}
	u, _ := url.Parse(raw)
	good := u.RawQuery

	tests := []struct {
		name  string
		query string
	}{
		{"RelayState swapped", strings.Replace(good, "RelayState=a+b", "RelayState=evil", 1)},
		{"SigAlg downgraded", strings.Replace(good,
			url.QueryEscape(SigAlgRSASHA256), url.QueryEscape(SigAlgRSASHA512), 1)},
		{"Signature truncated", strings.Replace(good, "&Signature=", "&Signature=AAAA", 1)},
		// Re-encoding a value the peer sent differently must fail: "+" and
		// "%20" decode to the same space, so a verifier that rebuilt the
		// signed string from decoded values would accept this.
		{"RelayState re-encoded", strings.Replace(good, "RelayState=a+b", "RelayState=a%20b", 1)},
		// A repeated parameter lets the verifier and the consumer read
		// different values.
		{"duplicate SAMLRequest", good + "&SAMLRequest=" + url.QueryEscape("junk")},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if tc.query == good {
				t.Fatal("test premise broken: the query was not modified")
			}
			if _, err := parseRedirect(tc.query, "SAMLRequest",
				[]*x509.Certificate{idp.cert}, false, true, defaultMaxResponseBytes); err == nil {
				t.Error("a tampered query string was accepted")
			}
		})
	}

	// The unmodified query must still verify, so the cases above fail for the
	// reason claimed and not because the fixture is broken.
	if _, err := parseRedirect(good, "SAMLRequest",
		[]*x509.Certificate{idp.cert}, false, true, defaultMaxResponseBytes); err != nil {
		t.Fatalf("the untampered query no longer verifies: %v", err)
	}
}

func TestRedirectBindingUnsignedRejectedWhenRequired(t *testing.T) {
	idp := newTestIdP(t, "rsa")
	b := newTestBuilder(t, idp, func(o *RequestOptions) {
		o.SigningKey = nil
		o.SigningCertificate = nil
	})
	req, err := b.BuildAuthnRequest()
	if err != nil {
		t.Fatalf("BuildAuthnRequest: %v", err)
	}
	raw, err := b.RedirectURL(req, "")
	if err != nil {
		t.Fatalf("RedirectURL: %v", err)
	}
	u, _ := url.Parse(raw)
	if strings.Contains(u.RawQuery, "Signature=") {
		t.Fatal("an unsigned builder produced a Signature parameter")
	}
	if _, err := parseRedirect(u.RawQuery, "SAMLRequest",
		[]*x509.Certificate{idp.cert}, false, true, defaultMaxResponseBytes); !errors.Is(err, ErrMissingSignature) {
		t.Errorf("got %v, want ErrMissingSignature", err)
	}
}

// TestRedirectBindingPreservesEndpointQuery checks that an SSO endpoint which
// already carries query parameters keeps them, and that they stay out of the
// signed string.
func TestRedirectBindingPreservesEndpointQuery(t *testing.T) {
	idp := newTestIdP(t, "rsa")
	b := newTestBuilder(t, idp, func(o *RequestOptions) {
		o.SSOServiceURL = testIdPSSOURL + "?tenant=acme"
	})
	req, err := b.BuildAuthnRequest()
	if err != nil {
		t.Fatalf("BuildAuthnRequest: %v", err)
	}
	raw, err := b.RedirectURL(req, "")
	if err != nil {
		t.Fatalf("RedirectURL: %v", err)
	}
	u, _ := url.Parse(raw)
	if !strings.HasPrefix(u.RawQuery, "tenant=acme&SAMLRequest=") {
		t.Errorf("endpoint query was not preserved: %s", u.RawQuery)
	}
	if _, err := parseRedirect(u.RawQuery, "SAMLRequest",
		[]*x509.Certificate{idp.cert}, false, true, defaultMaxResponseBytes); err != nil {
		t.Errorf("verification failed with an endpoint query parameter present: %v", err)
	}
}

// --- HTTP-POST binding ------------------------------------------------------

// verifyPostBinding decodes a POST-binding value and runs it through the same
// signature verification the ACS side uses, returning the element the signature
// covers.
func verifyPostBinding(t *testing.T, p *PostBinding, certs []*x509.Certificate) *xnode {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(p.Value)
	if err != nil {
		t.Fatalf("decoding POST value: %v", err)
	}
	root, err := parseXML(raw, defaultMaxDepth)
	if err != nil {
		t.Fatalf("parsing POST value: %v\n%s", err, raw)
	}
	sig, err := root.onlyChild(nsDSig, "Signature")
	if err != nil {
		t.Fatalf("finding the signature: %v\n%s", err, raw)
	}
	verified, err := verifySignature(root, sig, certs, false)
	if err != nil {
		t.Fatalf("verifying the signature we produced: %v\n%s", err, raw)
	}
	if verified.element != root {
		t.Fatal("the signature does not cover the root element")
	}
	return root
}

func TestAuthnRequestPostBindingSignature(t *testing.T) {
	for _, kind := range []string{"rsa", "ecdsa"} {
		t.Run(kind, func(t *testing.T) {
			idp := newTestIdP(t, kind)
			b := newTestBuilder(t, idp)
			req, err := b.BuildAuthnRequest()
			if err != nil {
				t.Fatalf("BuildAuthnRequest: %v", err)
			}
			p, err := b.PostBinding(req, "relay")
			if err != nil {
				t.Fatalf("PostBinding: %v", err)
			}
			if p.Field != "SAMLRequest" || p.URL != testIdPSSOURL {
				t.Errorf("PostBinding = %+v", p)
			}
			root := verifyPostBinding(t, p, []*x509.Certificate{idp.cert})
			if id, _ := root.attrValue("", "ID"); id != req.ID {
				t.Errorf("signed document ID = %q, want %q", id, req.ID)
			}

			// A tampered copy must not verify.
			raw, _ := base64.StdEncoding.DecodeString(p.Value)
			bad := strings.Replace(string(raw), testSPEntityID, "https://evil.example.com", 1)
			badRoot, err := parseXML([]byte(bad), defaultMaxDepth)
			if err != nil {
				t.Fatalf("parsing tampered request: %v", err)
			}
			badSig, err := badRoot.onlyChild(nsDSig, "Signature")
			if err != nil {
				t.Fatalf("finding the signature: %v", err)
			}
			if _, err := verifySignature(badRoot, badSig, []*x509.Certificate{idp.cert}, false); err == nil {
				t.Error("a tampered AuthnRequest verified")
			}
		})
	}
}

func TestPostBindingNeedsAKey(t *testing.T) {
	idp := newTestIdP(t, "rsa")
	b := newTestBuilder(t, idp, func(o *RequestOptions) { o.SigningKey = nil })
	req, err := b.BuildAuthnRequest()
	if err != nil {
		t.Fatalf("BuildAuthnRequest: %v", err)
	}
	if _, err := b.PostBinding(req, ""); !errors.Is(err, ErrNoSigningKey) {
		t.Errorf("got %v, want ErrNoSigningKey", err)
	}
}

func TestPostBindingHTMLFormEscapes(t *testing.T) {
	p := &PostBinding{
		URL:        `https://idp.example.com/sso?a="b"`,
		Field:      "SAMLRequest",
		Value:      "PHNhbWw+",
		RelayState: `<script>alert(1)</script>`,
	}
	form := p.HTMLForm()
	if strings.Contains(form, "<script>") {
		t.Errorf("RelayState was not escaped:\n%s", form)
	}
	if strings.Contains(form, `action="https://idp.example.com/sso?a="b""`) {
		t.Errorf("URL was not escaped:\n%s", form)
	}
	v := p.FormValues()
	if v.Get("SAMLRequest") != p.Value || v.Get("RelayState") != p.RelayState {
		t.Errorf("FormValues = %v", v)
	}
}

func TestBuilderRejectsBadConfiguration(t *testing.T) {
	idp := newTestIdP(t, "rsa")
	tests := []struct {
		name string
		opts RequestOptions
	}{
		{"no entity ID", RequestOptions{SSOServiceURL: testIdPSSOURL}},
		{"no SSO URL", RequestOptions{EntityID: testSPEntityID}},
		{"unknown algorithm", RequestOptions{
			EntityID: testSPEntityID, SSOServiceURL: testIdPSSOURL,
			SigningKey: idp.key, SignatureAlgorithm: "urn:made:up",
		}},
		{"SHA-1 refused for signing", RequestOptions{
			EntityID: testSPEntityID, SSOServiceURL: testIdPSSOURL,
			SigningKey: idp.key, SignatureAlgorithm: algRSASHA1,
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := NewRequestBuilder(tc.opts); err == nil {
				t.Error("configuration was accepted")
			}
		})
	}
}

// --- Single logout ----------------------------------------------------------

// sloPair builds the two ends of a logout conversation: the SP under test and
// a mock IdP that signs with idp's key.
func sloPair(t *testing.T, idp *testIdP, mutateSP ...func(*SLOOptions)) (sp, idpSide *SLO) {
	t.Helper()
	spOpts := SLOOptions{
		EntityID:                  testSPEntityID,
		IdPEntityID:               testIssuer,
		IdPCertificates:           []*x509.Certificate{idp.cert},
		SingleLogoutServiceURL:    testSPSLOURL,
		IdPSingleLogoutServiceURL: testIdPSLOURL,
		Clock:                     testClock,
		NewID:                     seqIDs("_sp1", "_sp2", "_sp3"),
	}
	for _, m := range mutateSP {
		m(&spOpts)
	}
	var err error
	if sp, err = NewSLO(spOpts); err != nil {
		t.Fatalf("NewSLO (SP): %v", err)
	}
	idpSide, err = NewSLO(SLOOptions{
		EntityID:                  testIssuer,
		IdPEntityID:               testSPEntityID,
		IdPCertificates:           []*x509.Certificate{idp.cert},
		SingleLogoutServiceURL:    testIdPSLOURL,
		IdPSingleLogoutServiceURL: testSPSLOURL,
		SigningKey:                idp.key,
		SigningCertificate:        idp.cert,
		Clock:                     testClock,
		NewID:                     seqIDs("_idp1", "_idp2", "_idp3"),
	})
	if err != nil {
		t.Fatalf("NewSLO (IdP): %v", err)
	}
	return sp, idpSide
}

func TestIdPInitiatedLogoutPost(t *testing.T) {
	idp := newTestIdP(t, "rsa")
	sp, idpSide := sloPair(t, idp)

	msg, err := idpSide.BuildLogoutRequest(testNameID, NameIDFormatEmailAddress, "_session1", "_session2")
	if err != nil {
		t.Fatalf("BuildLogoutRequest: %v", err)
	}
	p, err := idpSide.PostBinding(msg, "relay")
	if err != nil {
		t.Fatalf("PostBinding: %v", err)
	}
	verifyPostBinding(t, p, []*x509.Certificate{idp.cert})

	req, err := sp.ValidateLogoutRequestPOST(p.Value, p.RelayState)
	if err != nil {
		t.Fatalf("ValidateLogoutRequestPOST: %v", err)
	}
	if !req.Signed {
		t.Error("request was not reported as signed")
	}
	if req.NameID != testNameID {
		t.Errorf("NameID = %q", req.NameID)
	}
	if req.NameIDFormat != NameIDFormatEmailAddress {
		t.Errorf("NameIDFormat = %q", req.NameIDFormat)
	}
	if req.SessionIndex != "_session1" || len(req.SessionIndexes) != 2 {
		t.Errorf("SessionIndexes = %v", req.SessionIndexes)
	}
	if req.Issuer != testIssuer || req.Destination != testSPSLOURL {
		t.Errorf("Issuer = %q, Destination = %q", req.Issuer, req.Destination)
	}
	if req.RelayState != "relay" {
		t.Errorf("RelayState = %q", req.RelayState)
	}

	// The SP answers. It has no key here, so only the redirect binding — which
	// can carry an unsigned message — is available.
	resp, err := sp.BuildLogoutResponse(req)
	if err != nil {
		t.Fatalf("BuildLogoutResponse: %v", err)
	}
	if resp.InResponseTo != req.ID {
		t.Errorf("InResponseTo = %q, want %q", resp.InResponseTo, req.ID)
	}
	doc := string(resp.XML)
	if !strings.Contains(doc, `InResponseTo="`+req.ID+`"`) {
		t.Errorf("response does not quote the request ID:\n%s", doc)
	}
	if !strings.Contains(doc, `Value="`+StatusSuccess+`"`) {
		t.Errorf("response is not a Success:\n%s", doc)
	}
	if _, err := parseXML(resp.XML, defaultMaxDepth); err != nil {
		t.Fatalf("the response we built does not parse: %v", err)
	}
}

func TestIdPInitiatedLogoutRedirect(t *testing.T) {
	idp := newTestIdP(t, "rsa")
	sp, idpSide := sloPair(t, idp)

	msg, err := idpSide.BuildLogoutRequest(testNameID, NameIDFormatEmailAddress)
	if err != nil {
		t.Fatalf("BuildLogoutRequest: %v", err)
	}
	raw, err := idpSide.RedirectURL(msg, "relay state")
	if err != nil {
		t.Fatalf("RedirectURL: %v", err)
	}
	u, _ := url.Parse(raw)

	req, err := sp.ValidateLogoutRequestRedirect(u.RawQuery)
	if err != nil {
		t.Fatalf("ValidateLogoutRequestRedirect: %v", err)
	}
	if !req.Signed || req.NameID != testNameID || req.RelayState != "relay state" {
		t.Errorf("request = %+v", req)
	}
	if len(req.SessionIndexes) != 0 {
		t.Errorf("SessionIndexes = %v, want none", req.SessionIndexes)
	}
}

// TestUnsignedLogoutRequestRejected is the central anti-forgery case: with a
// certificate configured, an unsigned LogoutRequest must never be acted on,
// over either binding.
func TestUnsignedLogoutRequestRejected(t *testing.T) {
	idp := newTestIdP(t, "rsa")
	sp, idpSide := sloPair(t, idp)
	msg, err := idpSide.BuildLogoutRequest(testNameID, "")
	if err != nil {
		t.Fatalf("BuildLogoutRequest: %v", err)
	}

	t.Run("POST", func(t *testing.T) {
		// The raw, unsigned document, as an attacker would post it.
		b64 := base64.StdEncoding.EncodeToString(msg.XML)
		if _, err := sp.ValidateLogoutRequestPOST(b64, ""); !errors.Is(err, ErrNoSignature) {
			t.Errorf("got %v, want ErrNoSignature", err)
		}
	})

	t.Run("redirect", func(t *testing.T) {
		unsigned, err := NewSLO(SLOOptions{
			EntityID:                  testIssuer,
			IdPSingleLogoutServiceURL: testSPSLOURL,
			Clock:                     testClock,
			NewID:                     seqIDs("_x1"),
		})
		if err != nil {
			t.Fatalf("NewSLO: %v", err)
		}
		raw, err := unsigned.RedirectURL(msg, "")
		if err != nil {
			t.Fatalf("RedirectURL: %v", err)
		}
		u, _ := url.Parse(raw)
		if strings.Contains(u.RawQuery, "Signature=") {
			t.Fatal("test premise broken: the message is signed")
		}
		if _, err := sp.ValidateLogoutRequestRedirect(u.RawQuery); !errors.Is(err, ErrMissingSignature) {
			t.Errorf("got %v, want ErrMissingSignature", err)
		}
	})

	t.Run("wrong key", func(t *testing.T) {
		other := newTestIdP(t, "rsa")
		_, otherSide := sloPair(t, other)
		m, err := otherSide.BuildLogoutRequest(testNameID, "")
		if err != nil {
			t.Fatalf("BuildLogoutRequest: %v", err)
		}
		p, err := otherSide.PostBinding(m, "")
		if err != nil {
			t.Fatalf("PostBinding: %v", err)
		}
		if _, err := sp.ValidateLogoutRequestPOST(p.Value, ""); err == nil {
			t.Error("a logout request signed by the wrong key was accepted")
		}
	})
}

func TestLogoutRequestChecks(t *testing.T) {
	idp := newTestIdP(t, "rsa")

	build := func(t *testing.T, idpSide *SLO) string {
		t.Helper()
		m, err := idpSide.BuildLogoutRequest(testNameID, "")
		if err != nil {
			t.Fatalf("BuildLogoutRequest: %v", err)
		}
		p, err := idpSide.PostBinding(m, "")
		if err != nil {
			t.Fatalf("PostBinding: %v", err)
		}
		return p.Value
	}

	t.Run("wrong destination", func(t *testing.T) {
		sp, idpSide := sloPair(t, idp, func(o *SLOOptions) {
			o.SingleLogoutServiceURL = "https://sp.example.com/other-slo"
		})
		if _, err := sp.ValidateLogoutRequestPOST(build(t, idpSide), ""); !errors.Is(err, ErrConditions) {
			t.Errorf("got %v, want ErrConditions", err)
		}
	})

	t.Run("unconfigured destination", func(t *testing.T) {
		sp, idpSide := sloPair(t, idp, func(o *SLOOptions) { o.SingleLogoutServiceURL = "" })
		if _, err := sp.ValidateLogoutRequestPOST(build(t, idpSide), ""); err == nil {
			t.Error("a Destination was accepted with no configured SLO URL to compare it against")
		}
	})

	t.Run("wrong issuer", func(t *testing.T) {
		sp, idpSide := sloPair(t, idp, func(o *SLOOptions) { o.IdPEntityID = "https://other.example.com" })
		if _, err := sp.ValidateLogoutRequestPOST(build(t, idpSide), ""); !errors.Is(err, ErrConditions) {
			t.Errorf("got %v, want ErrConditions", err)
		}
	})

	t.Run("expired", func(t *testing.T) {
		_, idpSide := sloPair(t, idp)
		m, err := idpSide.BuildLogoutRequest(testNameID, "")
		if err != nil {
			t.Fatalf("BuildLogoutRequest: %v", err)
		}
		// Adding NotOnOrAfter would invalidate a signature, so the expiry
		// check is exercised on an unsigned message with a validator that has
		// explicitly opted out of signature checking.
		expired := strings.Replace(string(m.XML), ` Version="2.0"`,
			` Version="2.0" NotOnOrAfter="`+iso(testNow.Add(-time.Hour))+`"`, 1)
		if expired == string(m.XML) {
			t.Fatal("test premise broken: NotOnOrAfter was not injected")
		}
		lax, err := NewSLO(SLOOptions{
			EntityID:                        testSPEntityID,
			SingleLogoutServiceURL:          testSPSLOURL,
			IdPSingleLogoutServiceURL:       testIdPSLOURL,
			Clock:                           testClock,
			InsecureSkipSignatureValidation: true,
			NewID:                           seqIDs("_y1"),
		})
		if err != nil {
			t.Fatalf("NewSLO: %v", err)
		}
		if _, err := lax.ValidateLogoutRequestPOST(
			base64.StdEncoding.EncodeToString([]byte(expired)), ""); !errors.Is(err, ErrConditions) {
			t.Errorf("got %v, want ErrConditions", err)
		}
		// Within the window it is accepted, so the case above fails on the
		// clock and not on something else.
		fresh := strings.Replace(string(m.XML), ` Version="2.0"`,
			` Version="2.0" NotOnOrAfter="`+iso(testNow.Add(time.Hour))+`"`, 1)
		if _, err := lax.ValidateLogoutRequestPOST(
			base64.StdEncoding.EncodeToString([]byte(fresh)), ""); err != nil {
			t.Errorf("an unexpired request was rejected: %v", err)
		}
	})

	t.Run("no certificate configured", func(t *testing.T) {
		_, idpSide := sloPair(t, idp)
		bare, err := NewSLO(SLOOptions{
			EntityID:                  testSPEntityID,
			SingleLogoutServiceURL:    testSPSLOURL,
			IdPSingleLogoutServiceURL: testIdPSLOURL,
			Clock:                     testClock,
		})
		if err != nil {
			t.Fatalf("NewSLO: %v", err)
		}
		if _, err := bare.ValidateLogoutRequestPOST(build(t, idpSide), ""); !errors.Is(err, ErrNoCertificates) {
			t.Errorf("got %v, want ErrNoCertificates", err)
		}
	})
}

func TestSPInitiatedLogout(t *testing.T) {
	idp := newTestIdP(t, "rsa")
	sp, idpSide := sloPair(t, idp, func(o *SLOOptions) {
		o.SigningKey = idp.key
		o.SigningCertificate = idp.cert
	})

	req, err := sp.BuildLogoutRequest(testNameID, NameIDFormatEmailAddress, "_session1")
	if err != nil {
		t.Fatalf("BuildLogoutRequest: %v", err)
	}
	if req.ID != "_sp1" || req.Field != "SAMLRequest" || req.Destination != testIdPSLOURL {
		t.Errorf("message = %+v", req)
	}
	p, err := sp.PostBinding(req, "")
	if err != nil {
		t.Fatalf("PostBinding: %v", err)
	}
	incoming, err := idpSide.ValidateLogoutRequestPOST(p.Value, "")
	if err != nil {
		t.Fatalf("the IdP could not validate our LogoutRequest: %v", err)
	}
	if incoming.ID != req.ID {
		t.Errorf("IdP saw ID %q, want %q", incoming.ID, req.ID)
	}

	resp, err := idpSide.BuildLogoutResponse(incoming)
	if err != nil {
		t.Fatalf("BuildLogoutResponse: %v", err)
	}
	rp, err := idpSide.PostBinding(resp, "")
	if err != nil {
		t.Fatalf("PostBinding: %v", err)
	}
	got, err := sp.ValidateLogoutResponsePOST(rp.Value, req.ID, "")
	if err != nil {
		t.Fatalf("ValidateLogoutResponsePOST: %v", err)
	}
	if !got.Signed || got.StatusCode != StatusSuccess || got.InResponseTo != req.ID {
		t.Errorf("response = %+v", got)
	}

	// The same exchange over the redirect binding.
	raw, err := idpSide.RedirectURL(resp, "state")
	if err != nil {
		t.Fatalf("RedirectURL: %v", err)
	}
	u, _ := url.Parse(raw)
	got, err = sp.ValidateLogoutResponseRedirect(u.RawQuery, req.ID)
	if err != nil {
		t.Fatalf("ValidateLogoutResponseRedirect: %v", err)
	}
	if !got.Signed || got.RelayState != "state" {
		t.Errorf("response = %+v", got)
	}
}

// TestLogoutResponseInResponseToMismatch is the other half of the anti-forgery
// discipline: a response that answers a different request — or no request at
// all — must never confirm a logout.
func TestLogoutResponseInResponseToMismatch(t *testing.T) {
	idp := newTestIdP(t, "rsa")
	sp, idpSide := sloPair(t, idp)

	req, err := sp.BuildLogoutRequest(testNameID, "")
	if err != nil {
		t.Fatalf("BuildLogoutRequest: %v", err)
	}
	resp, err := idpSide.BuildLogoutResponse(&LogoutRequest{ID: req.ID})
	if err != nil {
		t.Fatalf("BuildLogoutResponse: %v", err)
	}
	p, err := idpSide.PostBinding(resp, "")
	if err != nil {
		t.Fatalf("PostBinding: %v", err)
	}

	if _, err := sp.ValidateLogoutResponsePOST(p.Value, "_someotherrequest", ""); !errors.Is(err, ErrInResponseTo) {
		t.Errorf("mismatched InResponseTo: got %v, want ErrInResponseTo", err)
	}
	if _, err := sp.ValidateLogoutResponsePOST(p.Value, "", ""); !errors.Is(err, ErrInResponseTo) {
		t.Errorf("unsolicited response: got %v, want ErrInResponseTo", err)
	}
	if _, err := sp.ValidateLogoutResponsePOST(p.Value, req.ID, ""); err != nil {
		t.Fatalf("the matching request ID was rejected: %v", err)
	}
}

func TestLogoutResponseNonSuccessRejected(t *testing.T) {
	idp := newTestIdP(t, "rsa")
	sp, idpSide := sloPair(t, idp)
	resp, err := idpSide.BuildLogoutResponseStatus(&LogoutRequest{ID: "_sp1"}, StatusPartialLogout, "some sessions remain")
	if err != nil {
		t.Fatalf("BuildLogoutResponseStatus: %v", err)
	}
	p, err := idpSide.PostBinding(resp, "")
	if err != nil {
		t.Fatalf("PostBinding: %v", err)
	}
	if _, err := sp.ValidateLogoutResponsePOST(p.Value, "_sp1", ""); !errors.Is(err, ErrLogoutStatus) {
		t.Errorf("got %v, want ErrLogoutStatus", err)
	}
}

func TestLogoutRedirectRejectsEnvelopedSignature(t *testing.T) {
	idp := newTestIdP(t, "rsa")
	sp, idpSide := sloPair(t, idp)
	msg, err := idpSide.BuildLogoutRequest(testNameID, "")
	if err != nil {
		t.Fatalf("BuildLogoutRequest: %v", err)
	}
	p, err := idpSide.PostBinding(msg, "")
	if err != nil {
		t.Fatalf("PostBinding: %v", err)
	}
	signedXML, _ := base64.StdEncoding.DecodeString(p.Value)

	// Deliver the enveloped-signed document over the redirect binding, with a
	// valid redirect signature too. The message must still be refused: two
	// signatures with different scopes is a wrapping opportunity, not extra
	// assurance.
	enc, err := DeflateEncode(signedXML)
	if err != nil {
		t.Fatalf("DeflateEncode: %v", err)
	}
	query := "SAMLRequest=" + url.QueryEscape(enc)
	if _, err := sp.ValidateLogoutRequestRedirect(query); err == nil {
		t.Error("a redirect message carrying an enveloped signature was accepted")
	}
}

func TestLogoutRejectsEncryptedID(t *testing.T) {
	idp := newTestIdP(t, "rsa")
	sp, _ := sloPair(t, idp, func(o *SLOOptions) { o.InsecureSkipSignatureValidation = true })
	doc := `<samlp:LogoutRequest xmlns:samlp="` + nsSAMLProtocol + `" xmlns:saml="` + nsSAMLAssertion + `"` +
		` ID="_lr1" Version="2.0" IssueInstant="` + iso(testNow) + `" Destination="` + testSPSLOURL + `">` +
		`<saml:Issuer>` + testIssuer + `</saml:Issuer>` +
		`<saml:EncryptedID/>` +
		`</samlp:LogoutRequest>`
	if _, err := sp.ValidateLogoutRequestPOST(
		base64.StdEncoding.EncodeToString([]byte(doc)), ""); !errors.Is(err, ErrEncrypted) {
		t.Errorf("got %v, want ErrEncrypted", err)
	}
}

// --- Metadata ---------------------------------------------------------------

type metadataFixture struct {
	entityID    string
	id          string
	signing     []*x509.Certificate
	encryption  []*x509.Certificate
	ssoBindings []string
	sloBindings []string
	validUntil  time.Time
	sign        bool
	signer      *testIdP
	prefix      string
	wrap        bool
}

func (f metadataFixture) build(t *testing.T) []byte {
	t.Helper()
	keyDescriptor := func(use string, cert *x509.Certificate) string {
		attr := ""
		if use != "" {
			attr = ` use="` + use + `"`
		}
		return `<md:KeyDescriptor` + attr + `><ds:KeyInfo><ds:X509Data><ds:X509Certificate>` +
			base64.StdEncoding.EncodeToString(cert.Raw) +
			`</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>`
	}
	var sb strings.Builder
	sb.WriteString(f.prefix)
	if f.wrap {
		sb.WriteString(`<md:EntitiesDescriptor xmlns:md="` + nsMetadata + `" xmlns:ds="` + nsDSig + `">`)
		sb.WriteString(`<md:EntityDescriptor entityID="https://other.example.com" ID="_other">`)
		sb.WriteString(`<md:IDPSSODescriptor protocolSupportEnumeration="` + nsSAMLProtocol + `">`)
		sb.WriteString(keyDescriptor("signing", f.signing[0]))
		sb.WriteString(`<md:SingleSignOnService Binding="` + BindingHTTPRedirect + `" Location="https://other.example.com/sso"/>`)
		sb.WriteString(`</md:IDPSSODescriptor></md:EntityDescriptor>`)
		sb.WriteString(`<md:EntityDescriptor entityID="` + f.entityID + `" ID="` + f.id + `">`)
	} else {
		sb.WriteString(`<md:EntityDescriptor xmlns:md="` + nsMetadata + `" xmlns:ds="` + nsDSig + `"`)
		sb.WriteString(` entityID="` + f.entityID + `" ID="` + f.id + `"`)
		if !f.validUntil.IsZero() {
			sb.WriteString(` validUntil="` + iso(f.validUntil) + `"`)
		}
		sb.WriteString(` cacheDuration="PT1H">`)
	}
	if f.sign {
		sb.WriteString(signatureMarker)
	}
	sb.WriteString(`<md:IDPSSODescriptor WantAuthnRequestsSigned="true" protocolSupportEnumeration="` + nsSAMLProtocol + `">`)
	for _, c := range f.signing {
		sb.WriteString(keyDescriptor("signing", c))
	}
	for _, c := range f.encryption {
		sb.WriteString(keyDescriptor("encryption", c))
	}
	for _, b := range f.ssoBindings {
		sb.WriteString(`<md:SingleSignOnService Binding="` + b + `" Location="` + testIdPSSOURL + `"/>`)
	}
	for _, b := range f.sloBindings {
		sb.WriteString(`<md:SingleLogoutService Binding="` + b + `" Location="` + testIdPSLOURL +
			`" ResponseLocation="` + testIdPSLOURL + `/response"/>`)
	}
	sb.WriteString(`<md:NameIDFormat>` + NameIDFormatEmailAddress + `</md:NameIDFormat>`)
	sb.WriteString(`<md:NameIDFormat>` + NameIDFormatPersistent + `</md:NameIDFormat>`)
	sb.WriteString(`</md:IDPSSODescriptor></md:EntityDescriptor>`)
	if f.wrap {
		sb.WriteString(`</md:EntitiesDescriptor>`)
	}

	doc := sb.String()
	if !f.sign {
		return []byte(doc)
	}
	signed, err := signEnveloped(doc, f.id, f.signer.key, f.signer.cert, SigAlgRSASHA256, defaultMaxDepth)
	if err != nil {
		t.Fatalf("signing metadata: %v", err)
	}
	return signed
}

func newMetadataFixture(idp *testIdP) metadataFixture {
	return metadataFixture{
		entityID:    testIssuer,
		id:          "_md1",
		signing:     []*x509.Certificate{idp.cert},
		ssoBindings: []string{BindingHTTPRedirect, BindingHTTPPost},
		sloBindings: []string{BindingHTTPRedirect},
	}
}

func TestParseIdPMetadata(t *testing.T) {
	idp := newTestIdP(t, "rsa")
	data := newMetadataFixture(idp).build(t)

	m, err := ParseIdPMetadata(data, MetadataOptions{Now: testClock})
	if err != nil {
		t.Fatalf("ParseIdPMetadata: %v", err)
	}
	if m.EntityID != testIssuer {
		t.Errorf("EntityID = %q", m.EntityID)
	}
	if m.Signed {
		t.Error("unsigned metadata reported as Signed")
	}
	if !m.WantAuthnRequestsSigned {
		t.Error("WantAuthnRequestsSigned was not read")
	}
	if m.CacheDuration.Raw != "PT1H" || m.CacheDuration.Fixed != time.Hour {
		t.Errorf("CacheDuration = %+v", m.CacheDuration)
	}
	if !m.CacheDuration.Present() {
		t.Error("CacheDuration.Present() = false")
	}
	if len(m.SigningCertificates) != 1 || !m.SigningCertificates[0].Equal(idp.cert) {
		t.Errorf("SigningCertificates = %v", m.SigningCertificates)
	}
	if got := m.SSOURL(BindingHTTPRedirect); got != testIdPSSOURL {
		t.Errorf("SSOURL(redirect) = %q", got)
	}
	if got := m.SSOURL(BindingSOAP); got != "" {
		t.Errorf("SSOURL(soap) = %q, want empty", got)
	}
	if got := m.SLOURL(BindingHTTPRedirect); got != testIdPSLOURL {
		t.Errorf("SLOURL = %q", got)
	}
	if got := m.SLOResponseURL(BindingHTTPRedirect); got != testIdPSLOURL+"/response" {
		t.Errorf("SLOResponseURL = %q", got)
	}
	if len(m.NameIDFormats) != 2 {
		t.Errorf("NameIDFormats = %v", m.NameIDFormats)
	}

	// The parsed metadata must be able to configure the rest of the package.
	o := Options{Audience: testSPEntityID}
	m.ApplyTo(&o)
	if len(o.IdPCertificates) != 1 {
		t.Errorf("ApplyTo left %d certificates", len(o.IdPCertificates))
	}
	ro := RequestOptions{EntityID: testSPEntityID}
	if err := m.ApplyToRequestOptions(&ro, BindingHTTPRedirect); err != nil {
		t.Fatalf("ApplyToRequestOptions: %v", err)
	}
	if _, err := NewRequestBuilder(ro); err != nil {
		t.Fatalf("metadata did not yield a usable RequestOptions: %v", err)
	}
	so := SLOOptions{EntityID: testSPEntityID}
	if err := m.ApplyToSLOOptions(&so, BindingHTTPRedirect); err != nil {
		t.Fatalf("ApplyToSLOOptions: %v", err)
	}
	if so.IdPSingleLogoutServiceURL != testIdPSLOURL || so.IdPEntityID != testIssuer {
		t.Errorf("SLOOptions = %+v", so)
	}
	if _, err := NewSLO(so); err != nil {
		t.Fatalf("metadata did not yield a usable SLOOptions: %v", err)
	}
}

// TestMetadataMultipleKeyDescriptors covers a key rollover, where the IdP
// publishes both the outgoing and incoming signing certificate, and the
// use-less KeyDescriptor the schema says is valid for both roles.
func TestMetadataMultipleKeyDescriptors(t *testing.T) {
	a := newTestIdP(t, "rsa")
	b := newTestIdP(t, "ecdsa")
	enc := newTestIdP(t, "rsa")

	f := newMetadataFixture(a)
	f.signing = []*x509.Certificate{a.cert, b.cert}
	f.encryption = []*x509.Certificate{enc.cert}
	m, err := ParseIdPMetadata(f.build(t), MetadataOptions{Now: testClock})
	if err != nil {
		t.Fatalf("ParseIdPMetadata: %v", err)
	}
	if len(m.SigningCertificates) != 2 {
		t.Fatalf("SigningCertificates = %d, want 2", len(m.SigningCertificates))
	}
	if !m.SigningCertificates[0].Equal(a.cert) || !m.SigningCertificates[1].Equal(b.cert) {
		t.Error("signing certificates are not in document order")
	}
	if len(m.EncryptionCertificates) != 1 || !m.EncryptionCertificates[0].Equal(enc.cert) {
		t.Errorf("EncryptionCertificates = %v", m.EncryptionCertificates)
	}

	// A KeyDescriptor with no use attribute counts for both roles.
	data := strings.Replace(string(f.build(t)), ` use="encryption"`, "", 1)
	m, err = ParseIdPMetadata([]byte(data), MetadataOptions{Now: testClock})
	if err != nil {
		t.Fatalf("ParseIdPMetadata: %v", err)
	}
	if len(m.SigningCertificates) != 3 || len(m.EncryptionCertificates) != 1 {
		t.Errorf("use-less KeyDescriptor: %d signing, %d encryption",
			len(m.SigningCertificates), len(m.EncryptionCertificates))
	}
}

func TestMetadataRejections(t *testing.T) {
	idp := newTestIdP(t, "rsa")

	t.Run("DOCTYPE", func(t *testing.T) {
		f := newMetadataFixture(idp)
		f.prefix = `<!DOCTYPE md:EntityDescriptor [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>`
		if _, err := ParseIdPMetadata(f.build(t), MetadataOptions{Now: testClock}); !errors.Is(err, ErrDoctype) {
			t.Errorf("got %v, want ErrDoctype", err)
		}
	})

	t.Run("entity reference", func(t *testing.T) {
		f := newMetadataFixture(idp)
		data := strings.Replace(string(f.build(t)), testIdPSSOURL, "&xxe;", 1)
		if _, err := ParseIdPMetadata([]byte(data), MetadataOptions{Now: testClock}); !errors.Is(err, ErrDoctype) {
			t.Errorf("got %v, want ErrDoctype", err)
		}
	})

	t.Run("no SSO endpoint", func(t *testing.T) {
		f := newMetadataFixture(idp)
		f.ssoBindings = nil
		if _, err := ParseIdPMetadata(f.build(t), MetadataOptions{Now: testClock}); !errors.Is(err, ErrNoSSOService) {
			t.Errorf("got %v, want ErrNoSSOService", err)
		}
	})

	t.Run("no signing certificate", func(t *testing.T) {
		f := newMetadataFixture(idp)
		f.signing = nil
		f.encryption = []*x509.Certificate{idp.cert}
		if _, err := ParseIdPMetadata(f.build(t), MetadataOptions{Now: testClock}); !errors.Is(err, ErrNoSigningCertificate) {
			t.Errorf("got %v, want ErrNoSigningCertificate", err)
		}
	})

	t.Run("endpoint without Location", func(t *testing.T) {
		f := newMetadataFixture(idp)
		data := strings.Replace(string(f.build(t)), ` Location="`+testIdPSSOURL+`"`, "", 1)
		if _, err := ParseIdPMetadata([]byte(data), MetadataOptions{Now: testClock}); err == nil {
			t.Error("an endpoint with no Location was accepted")
		}
	})

	t.Run("expired", func(t *testing.T) {
		f := newMetadataFixture(idp)
		f.validUntil = testNow.Add(-time.Hour)
		if _, err := ParseIdPMetadata(f.build(t), MetadataOptions{Now: testClock}); !errors.Is(err, ErrMetadataExpired) {
			t.Errorf("got %v, want ErrMetadataExpired", err)
		}
		if _, err := ParseIdPMetadata(f.build(t), MetadataOptions{Now: testClock, SkipValidUntil: true}); err != nil {
			t.Errorf("SkipValidUntil did not disable the check: %v", err)
		}
	})

	t.Run("too large", func(t *testing.T) {
		f := newMetadataFixture(idp)
		if _, err := ParseIdPMetadata(f.build(t), MetadataOptions{Now: testClock, MaxBytes: 16}); !errors.Is(err, ErrTooLarge) {
			t.Errorf("got %v, want ErrTooLarge", err)
		}
	})

	t.Run("wrong root", func(t *testing.T) {
		if _, err := ParseIdPMetadata([]byte(`<foo/>`), MetadataOptions{Now: testClock}); err == nil {
			t.Error("a non-metadata document was accepted")
		}
	})

	t.Run("SP-only entity", func(t *testing.T) {
		data, err := GenerateSPMetadata(SPMetadataOptions{
			EntityID:                    testSPEntityID,
			AssertionConsumerServiceURL: testACS,
		})
		if err != nil {
			t.Fatalf("GenerateSPMetadata: %v", err)
		}
		if _, err := ParseIdPMetadata(data, MetadataOptions{Now: testClock}); !errors.Is(err, ErrNoIDPDescriptor) {
			t.Errorf("got %v, want ErrNoIDPDescriptor", err)
		}
	})
}

func TestMetadataEntitiesDescriptorSelection(t *testing.T) {
	idp := newTestIdP(t, "rsa")
	f := newMetadataFixture(idp)
	f.wrap = true
	data := f.build(t)

	if _, err := ParseIdPMetadata(data, MetadataOptions{Now: testClock}); !errors.Is(err, ErrNoEntityDescriptor) {
		t.Errorf("an ambiguous aggregate was accepted: %v", err)
	}
	m, err := ParseIdPMetadata(data, MetadataOptions{Now: testClock, EntityID: testIssuer})
	if err != nil {
		t.Fatalf("ParseIdPMetadata: %v", err)
	}
	if m.EntityID != testIssuer {
		t.Errorf("EntityID = %q", m.EntityID)
	}
	if _, err := ParseIdPMetadata(data, MetadataOptions{Now: testClock, EntityID: "https://nobody.example"}); !errors.Is(err, ErrNoEntityDescriptor) {
		t.Errorf("got %v, want ErrNoEntityDescriptor", err)
	}
}

func TestMetadataSignatureVerification(t *testing.T) {
	signer := newTestIdP(t, "rsa")
	idp := newTestIdP(t, "rsa")

	f := newMetadataFixture(idp)
	f.sign = true
	f.signer = signer
	data := f.build(t)

	m, err := ParseIdPMetadata(data, MetadataOptions{
		Now:          testClock,
		TrustAnchors: []*x509.Certificate{signer.cert},
	})
	if err != nil {
		t.Fatalf("ParseIdPMetadata with the right anchor: %v", err)
	}
	if !m.Signed {
		t.Error("verified metadata not reported as Signed")
	}
	// The signing certificate published inside the document is what the IdP
	// signs assertions with; the trust anchor is a different key.
	if len(m.SigningCertificates) != 1 || !m.SigningCertificates[0].Equal(idp.cert) {
		t.Error("the published signing certificate was not returned")
	}

	other := newTestIdP(t, "rsa")
	if _, err := ParseIdPMetadata(data, MetadataOptions{
		Now: testClock, TrustAnchors: []*x509.Certificate{other.cert},
	}); err == nil {
		t.Error("metadata verified against an unrelated trust anchor")
	}

	// Tampering with a signed document must be caught.
	tampered := strings.Replace(string(data), testIdPSSOURL, "https://evil.example.com/sso", 1)
	if _, err := ParseIdPMetadata([]byte(tampered), MetadataOptions{
		Now: testClock, TrustAnchors: []*x509.Certificate{signer.cert},
	}); err == nil {
		t.Error("tampered signed metadata was accepted")
	}

	// An unsigned document must be refused when an anchor is supplied: the
	// caller asked for verified metadata and must not silently get TOFU.
	unsigned := newMetadataFixture(idp).build(t)
	if _, err := ParseIdPMetadata(unsigned, MetadataOptions{
		Now: testClock, TrustAnchors: []*x509.Certificate{signer.cert},
	}); !errors.Is(err, ErrNoSignature) {
		t.Errorf("got %v, want ErrNoSignature", err)
	}

	// With no anchor the signature is simply not consulted, and Signed says so.
	m, err = ParseIdPMetadata(data, MetadataOptions{Now: testClock})
	if err != nil {
		t.Fatalf("ParseIdPMetadata without an anchor: %v", err)
	}
	if m.Signed {
		t.Error("Signed is true although no trust anchor was supplied")
	}
}

func TestGenerateSPMetadata(t *testing.T) {
	idp := newTestIdP(t, "rsa")
	data, err := GenerateSPMetadata(SPMetadataOptions{
		EntityID:                    testSPEntityID,
		ID:                          "_spmd1",
		AssertionConsumerServiceURL: testACS,
		SingleLogoutServiceURL:      testSPSLOURL,
		NameIDFormats:               []string{NameIDFormatEmailAddress},
		SigningCertificate:          idp.cert,
		AuthnRequestsSigned:         true,
		WantAssertionsSigned:        true,
		ValidUntil:                  testNow.Add(24 * time.Hour),
	})
	if err != nil {
		t.Fatalf("GenerateSPMetadata: %v", err)
	}
	root, err := parseXML(data, defaultMaxDepth)
	if err != nil {
		t.Fatalf("the metadata we generated does not parse: %v\n%s", err, data)
	}
	if !root.is(nsMetadata, "EntityDescriptor") {
		t.Fatalf("root is <%s>", root.local)
	}
	if v, _ := root.attrValue("", "entityID"); v != testSPEntityID {
		t.Errorf("entityID = %q", v)
	}
	sp, err := root.onlyChild(nsMetadata, "SPSSODescriptor")
	if err != nil {
		t.Fatalf("SPSSODescriptor: %v", err)
	}
	if v, _ := sp.attrValue("", "AuthnRequestsSigned"); v != "true" {
		t.Errorf("AuthnRequestsSigned = %q", v)
	}
	if v, _ := sp.attrValue("", "WantAssertionsSigned"); v != "true" {
		t.Errorf("WantAssertionsSigned = %q", v)
	}
	acs, err := sp.onlyChild(nsMetadata, "AssertionConsumerService")
	if err != nil {
		t.Fatalf("AssertionConsumerService: %v", err)
	}
	if v, _ := acs.attrValue("", "Location"); v != testACS {
		t.Errorf("ACS Location = %q", v)
	}
	if v, _ := acs.attrValue("", "Binding"); v != BindingHTTPPost {
		t.Errorf("ACS Binding = %q", v)
	}
	// The published certificate must round-trip.
	kd, err := sp.onlyChild(nsMetadata, "KeyDescriptor")
	if err != nil {
		t.Fatalf("KeyDescriptor: %v", err)
	}
	signing, _, err := keyDescriptors(sp)
	if err != nil {
		t.Fatalf("keyDescriptors: %v", err)
	}
	if len(signing) != 1 || !signing[0].Equal(idp.cert) {
		t.Errorf("published certificate did not round-trip (%d found)", len(signing))
	}
	if v, _ := kd.attrValue("", "use"); v != "signing" {
		t.Errorf("KeyDescriptor use = %q", v)
	}

	if _, err := GenerateSPMetadata(SPMetadataOptions{AssertionConsumerServiceURL: testACS}); err == nil {
		t.Error("metadata was generated with no entity ID")
	}
	if _, err := GenerateSPMetadata(SPMetadataOptions{EntityID: testSPEntityID}); err == nil {
		t.Error("metadata was generated with no ACS URL")
	}
}
