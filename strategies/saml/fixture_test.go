package saml

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"math/big"
	"strings"
	"testing"
	"time"
)

// This file builds signed SAMLResponse fixtures programmatically so that the
// suite is self-contained and deterministic: keys and certificates are
// generated in-process, and every signature is produced by the same
// canonicalization code path that verification uses.
//
// That last point is worth being explicit about: because signing and verifying
// share canonicalize(), a canonicalization *bug* would be invisible to these
// tests. The known-answer cases in c14n_test.go exist precisely to pin the
// canonical form independently of this round trip.

const (
	testAudience = "https://sp.example.com/metadata"
	testACS      = "https://sp.example.com/acs"
	testIssuer   = "https://idp.example.com/entity"
	testNameID   = "alice@example.com"

	// Markers standing in for the signatures while the document is built.
	// They are XML comments, which canonicalization discards, so leaving one
	// in place while a digest is computed cannot affect the result.
	responseSigMarker  = "<!--RESPONSE-SIGNATURE-->"
	assertionSigMarker = "<!--ASSERTION-SIGNATURE-->"
)

// testNow is the fixed instant every fixture and strategy clock is anchored to.
var testNow = time.Date(2026, 1, 2, 15, 4, 5, 0, time.UTC)

// Algorithm URIs used by the fixtures.
const (
	algRSASHA256    = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
	algRSASHA512    = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512"
	algRSAPSS256    = "http://www.w3.org/2007/05/xmldsig-more#sha256-rsa-MGF1"
	algECDSASHA256  = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256"
	algRSASHA1      = "http://www.w3.org/2000/09/xmldsig#rsa-sha1"
	algDigestSHA256 = "http://www.w3.org/2001/04/xmlenc#sha256"
	algDigestSHA512 = "http://www.w3.org/2001/04/xmlenc#sha512"
	algDigestSHA1   = "http://www.w3.org/2000/09/xmldsig#sha1"
)

// testIdP is a mock identity provider holding a freshly generated key pair and
// a self-signed certificate.
type testIdP struct {
	key  crypto.Signer
	cert *x509.Certificate
}

// newTestIdP generates an IdP with an "rsa" or "ecdsa" signing key.
func newTestIdP(t *testing.T, kind string) *testIdP {
	t.Helper()
	var (
		key crypto.Signer
		err error
	)
	switch kind {
	case "rsa":
		key, err = rsa.GenerateKey(rand.Reader, 2048)
	case "ecdsa":
		key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	default:
		t.Fatalf("unknown key kind %q", kind)
	}
	if err != nil {
		t.Fatalf("generating %s key: %v", kind, err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-idp"},
		NotBefore:             testNow.Add(-24 * time.Hour),
		NotAfter:              testNow.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	return &testIdP{key: key, cert: cert}
}

// fixture describes one SAMLResponse to build. The zero value is not usable;
// use newFixture.
type fixture struct {
	idp *testIdP

	responseID   string
	assertionID  string
	issuer       string
	nameID       string
	audience     string
	recipient    string
	destination  string
	inResponseTo string
	statusCode   string
	notBefore    time.Time
	notOnOrAfter time.Time

	// signTarget is "assertion", "response", "both", or "" for unsigned.
	signTarget string
	sigAlg     string
	digestAlg  string
	c14nAlg    string
	transforms []string
	prefixList string
	embedCert  bool

	// signWith overrides the key used to produce the SignatureValue, so a
	// response can be signed by the wrong party.
	signWith crypto.Signer

	// postSign rewrites the finished XML. Signature-wrapping and tampering
	// tests use it to mutate a document that was correctly signed.
	postSign func(string) string

	// encrypt, when set, replaces the whole saml:Assertion element with
	// whatever it returns — normally a saml:EncryptedAssertion wrapping it.
	// It runs after any assertion-level signature has been applied and
	// before any response-level one, which is the order a real identity
	// provider works in: sign the assertion, encrypt it, then sign the
	// response around the ciphertext.
	encrypt func(t *testing.T, assertionXML string) string

	// extraAssertions are rendered verbatim after the primary assertion. The
	// multi-assertion tests use it.
	extraAssertions string

	// subjectID overrides the saml:NameID element of the subject, so that a
	// saml:EncryptedID can take its place.
	subjectID string
}

// subjectIDXML renders the subject identifier element.
func (f *fixture) subjectIDXML() string {
	if f.subjectID != "" {
		return f.subjectID
	}
	return `<saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">` + f.nameID + `</saml:NameID>`
}

// newFixture returns a fixture that produces a valid, correctly signed
// response: RSA-SHA256, exclusive canonicalization, assertion-level signature.
func newFixture(idp *testIdP) *fixture {
	return &fixture{
		idp:          idp,
		responseID:   "_response1",
		assertionID:  "_assertion1",
		issuer:       testIssuer,
		nameID:       testNameID,
		audience:     testAudience,
		recipient:    testACS,
		destination:  testACS,
		inResponseTo: "_request1",
		statusCode:   StatusSuccess,
		notBefore:    testNow.Add(-5 * time.Minute),
		notOnOrAfter: testNow.Add(5 * time.Minute),
		signTarget:   "assertion",
		sigAlg:       algRSASHA256,
		digestAlg:    algDigestSHA256,
		c14nAlg:      AlgC14NExclusive,
		transforms:   []string{AlgEnvelopedSignature, AlgC14NExclusive},
	}
}

func iso(t time.Time) string { return t.UTC().Format(time.RFC3339) }

func attrIf(name, value string) string {
	if value == "" {
		return ""
	}
	return ` ` + name + `="` + value + `"`
}

// document renders the response with sigMarker standing in for the signature.
func (f *fixture) document() string {
	assertion := `<saml:Assertion ID="` + f.assertionID + `" Version="2.0" IssueInstant="` + iso(testNow) + `">` +
		`<saml:Issuer>` + f.issuer + `</saml:Issuer>`
	if f.signTarget == "assertion" || f.signTarget == "both" {
		assertion += assertionSigMarker
	}
	assertion += `
    <saml:Subject>
      ` + f.subjectIDXML() + `
      <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <saml:SubjectConfirmationData` +
		attrIf("Recipient", f.recipient) +
		attrIf("NotOnOrAfter", isoOrEmpty(f.notOnOrAfter)) +
		attrIf("InResponseTo", f.inResponseTo) + `/>
      </saml:SubjectConfirmation>
    </saml:Subject>
    <saml:Conditions` +
		attrIf("NotBefore", isoOrEmpty(f.notBefore)) +
		attrIf("NotOnOrAfter", isoOrEmpty(f.notOnOrAfter)) + `>
      <saml:AudienceRestriction><saml:Audience>` + f.audience + `</saml:Audience></saml:AudienceRestriction>
    </saml:Conditions>
    <saml:AuthnStatement AuthnInstant="` + iso(testNow) + `" SessionIndex="_session1">
      <saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></saml:AuthnContext>
    </saml:AuthnStatement>
    <saml:AttributeStatement>
      <saml:Attribute Name="email"><saml:AttributeValue>` + f.nameID + `</saml:AttributeValue></saml:Attribute>
      <saml:Attribute Name="groups"><saml:AttributeValue>staff</saml:AttributeValue><saml:AttributeValue>admin</saml:AttributeValue></saml:Attribute>
    </saml:AttributeStatement>
  </saml:Assertion>`

	doc := `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"` +
		` xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="` + f.responseID + `"` +
		` Version="2.0" IssueInstant="` + iso(testNow) + `"` +
		attrIf("Destination", f.destination) +
		attrIf("InResponseTo", f.inResponseTo) + `>` +
		`<saml:Issuer>` + f.issuer + `</saml:Issuer>`
	if f.signTarget == "response" || f.signTarget == "both" {
		doc += responseSigMarker
	}
	doc += `
  <samlp:Status><samlp:StatusCode Value="` + f.statusCode + `"/></samlp:Status>
  ` + assertion + f.extraAssertions + `
</samlp:Response>`
	return doc
}

func isoOrEmpty(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return iso(t)
}

// signatureXML renders a ds:Signature for the given reference.
func (f *fixture) signatureXML(refID, digest string) string {
	transforms := ""
	for _, tr := range f.transforms {
		if tr == AlgC14NExclusive && f.prefixList != "" {
			transforms += `<ds:Transform Algorithm="` + tr + `">` +
				`<ec:InclusiveNamespaces xmlns:ec="` + nsExcC14N + `" PrefixList="` + f.prefixList + `"/>` +
				`</ds:Transform>`
			continue
		}
		transforms += `<ds:Transform Algorithm="` + tr + `"/>`
	}
	keyInfo := ""
	if f.embedCert {
		keyInfo = `<ds:KeyInfo><ds:X509Data><ds:X509Certificate>` +
			base64.StdEncoding.EncodeToString(f.idp.cert.Raw) +
			`</ds:X509Certificate></ds:X509Data></ds:KeyInfo>`
	}
	return `<ds:Signature xmlns:ds="` + nsDSig + `">` +
		`<ds:SignedInfo>` +
		`<ds:CanonicalizationMethod Algorithm="` + f.c14nAlg + `"/>` +
		`<ds:SignatureMethod Algorithm="` + f.sigAlg + `"/>` +
		`<ds:Reference URI="#` + refID + `">` +
		`<ds:Transforms>` + transforms + `</ds:Transforms>` +
		`<ds:DigestMethod Algorithm="` + f.digestAlg + `"/>` +
		`<ds:DigestValue>` + digest + `</ds:DigestValue>` +
		`</ds:Reference>` +
		`</ds:SignedInfo>` +
		`<ds:SignatureValue></ds:SignatureValue>` +
		keyInfo +
		`</ds:Signature>`
}

// refC14N is the canonicalization the reference transform chain selects.
func (f *fixture) refC14N() c14nOptions {
	opts := c14nOptions{}
	for _, tr := range f.transforms {
		if o, err := c14nModeFor(tr); err == nil {
			opts = o
		}
	}
	opts.inclusivePrefixes = strings.Fields(f.prefixList)
	return opts
}

// xml builds the finished SAMLResponse document. Signatures are applied
// innermost first, so a response-level signature covers the assertion-level one
// exactly as a real identity provider would produce it.
func (f *fixture) xml(t *testing.T) string {
	t.Helper()
	doc := f.document()
	if f.signTarget == "assertion" || f.signTarget == "both" {
		doc = f.addSignature(t, doc, assertionSigMarker, f.assertionID)
	}
	if f.encrypt != nil {
		doc = f.replaceAssertion(t, doc, f.encrypt)
	}
	if f.signTarget == "response" || f.signTarget == "both" {
		doc = f.addSignature(t, doc, responseSigMarker, f.responseID)
	}
	doc = strings.ReplaceAll(doc, assertionSigMarker, "")
	doc = strings.ReplaceAll(doc, responseSigMarker, "")
	if f.postSign != nil {
		doc = f.postSign(doc)
	}
	return doc
}

// replaceAssertion swaps the primary saml:Assertion element for whatever fn
// returns.
//
// The extracted element carries an explicit xmlns:saml declaration, which is
// what a real encryptor serializes: the fragment has to stand on its own once
// it is out of the response. Adding the declaration does not disturb an
// assertion-level signature, because exclusive canonicalization renders the
// visibly-utilized saml prefix on the apex element either way.
func (f *fixture) replaceAssertion(t *testing.T, doc string, fn func(*testing.T, string) string) string {
	t.Helper()
	const openTag = `<saml:Assertion `
	const closeTag = `</saml:Assertion>`
	start := strings.Index(doc, openTag)
	end := strings.LastIndex(doc, closeTag)
	if start < 0 || end < 0 {
		t.Fatalf("no saml:Assertion element in fixture:\n%s", doc)
	}
	end += len(closeTag)
	element := doc[start:end]
	fragment := openTag + `xmlns:saml="` + nsSAMLAssertion + `" ` + element[len(openTag):]
	return doc[:start] + fn(t, fragment) + doc[end:]
}

// addSignature digests the element refID identifies, then substitutes a
// ds:Signature for marker and fills in its SignatureValue.
func (f *fixture) addSignature(t *testing.T, doc, marker, refID string) string {
	t.Helper()
	root, err := parseXML([]byte(doc), defaultMaxDepth)
	if err != nil {
		t.Fatalf("parsing fixture: %v\n%s", err, doc)
	}
	target, err := resolveIDRef(root, refID)
	if err != nil {
		t.Fatalf("resolving #%s: %v", refID, err)
	}
	// The signature is not in the tree yet, which is precisely the node set
	// the enveloped-signature transform produces once it is.
	canon, err := canonicalize(target, f.refC14N())
	if err != nil {
		t.Fatalf("canonicalizing reference: %v", err)
	}
	digest := f.hash(t, f.digestAlg, canon)
	sigXML := f.signatureXML(refID, base64.StdEncoding.EncodeToString(digest))
	doc = strings.Replace(doc, marker, sigXML, 1)
	return f.fillSignatureValue(t, doc)
}

// fillSignatureValue canonicalizes the one SignedInfo whose SignatureValue is
// still empty, signs it, and substitutes the result.
func (f *fixture) fillSignatureValue(t *testing.T, doc string) string {
	t.Helper()
	root, err := parseXML([]byte(doc), defaultMaxDepth)
	if err != nil {
		t.Fatalf("parsing signed fixture: %v\n%s", err, doc)
	}
	var signedInfo *xnode
	root.walk(func(n *xnode) {
		if !n.is(nsDSig, "Signature") {
			return
		}
		sv, err := n.onlyChild(nsDSig, "SignatureValue")
		if err != nil || strings.TrimSpace(sv.textContent()) != "" {
			return
		}
		si, err := n.onlyChild(nsDSig, "SignedInfo")
		if err == nil {
			signedInfo = si
		}
	})
	if signedInfo == nil {
		t.Fatal("no unsigned ds:SignedInfo in fixture")
	}
	// An algorithm the package refuses is still signed here — with exclusive
	// c14n — so that rejection tests fail on the algorithm URI rather than on
	// a fixture that could not be built.
	siOpts, err := c14nModeFor(f.c14nAlg)
	if err != nil {
		siOpts = c14nOptions{exclusive: true}
	}
	canonSI, err := canonicalize(signedInfo, siOpts)
	if err != nil {
		t.Fatalf("canonicalizing SignedInfo: %v", err)
	}
	value := f.sign(t, canonSI)
	return strings.Replace(doc,
		"<ds:SignatureValue></ds:SignatureValue>",
		"<ds:SignatureValue>"+base64.StdEncoding.EncodeToString(value)+"</ds:SignatureValue>", 1)
}

// hash applies a DigestMethod URI.
func (f *fixture) hash(t *testing.T, uri string, data []byte) []byte {
	t.Helper()
	alg, ok := digestAlgorithms[uri]
	if !ok {
		// Unknown digest URIs are used by rejection tests; any hash will do
		// because verification refuses the URI before comparing.
		alg = digestAlgorithms[algDigestSHA256]
	}
	fn, err := newHash(alg.hash)
	if err != nil {
		t.Fatalf("newHash: %v", err)
	}
	return fn(data)
}

// sign produces the SignatureValue over canonical SignedInfo bytes, in the
// encoding xmldsig expects (raw r||s for ECDSA, not ASN.1).
func (f *fixture) sign(t *testing.T, canonicalSignedInfo []byte) []byte {
	t.Helper()
	alg, ok := signatureAlgorithms[f.sigAlg]
	if !ok {
		alg = signatureAlgorithms[algRSASHA256]
	}
	fn, err := newHash(alg.hash)
	if err != nil {
		t.Fatalf("newHash: %v", err)
	}
	digest := fn(canonicalSignedInfo)

	key := f.idp.key
	if f.signWith != nil {
		key = f.signWith
	}
	switch alg.kind {
	case sigRSAPKCS1:
		rsaKey, ok := key.(*rsa.PrivateKey)
		if !ok {
			t.Fatalf("signature algorithm %q needs an RSA key", f.sigAlg)
		}
		out, err := rsa.SignPKCS1v15(rand.Reader, rsaKey, alg.hash, digest)
		if err != nil {
			t.Fatalf("SignPKCS1v15: %v", err)
		}
		return out
	case sigRSAPSS:
		rsaKey, ok := key.(*rsa.PrivateKey)
		if !ok {
			t.Fatalf("signature algorithm %q needs an RSA key", f.sigAlg)
		}
		out, err := rsa.SignPSS(rand.Reader, rsaKey, alg.hash, digest, &rsa.PSSOptions{
			SaltLength: rsa.PSSSaltLengthEqualsHash,
			Hash:       alg.hash,
		})
		if err != nil {
			t.Fatalf("SignPSS: %v", err)
		}
		return out
	case sigECDSA:
		ecKey, ok := key.(*ecdsa.PrivateKey)
		if !ok {
			t.Fatalf("signature algorithm %q needs an ECDSA key", f.sigAlg)
		}
		r, s, err := ecdsa.Sign(rand.Reader, ecKey, digest)
		if err != nil {
			t.Fatalf("ecdsa.Sign: %v", err)
		}
		size := (ecKey.Curve.Params().BitSize + 7) / 8
		out := make([]byte, 2*size)
		r.FillBytes(out[:size])
		s.FillBytes(out[size:])
		return out
	}
	t.Fatalf("unhandled signature kind for %q", f.sigAlg)
	return nil
}

// encode returns the base64 SAMLResponse form value.
func (f *fixture) encode(t *testing.T) string {
	t.Helper()
	return base64.StdEncoding.EncodeToString([]byte(f.xml(t)))
}

// strategy builds a Strategy configured for this fixture's IdP, applying any
// option overrides.
func (f *fixture) strategy(overrides ...func(*Options)) *Strategy {
	opts := Options{
		IdPCertificates:             []*x509.Certificate{f.idp.cert},
		Audience:                    testAudience,
		AssertionConsumerServiceURL: testACS,
		Clock:                       func() time.Time { return testNow },
	}
	for _, o := range overrides {
		o(&opts)
	}
	return New(opts)
}
