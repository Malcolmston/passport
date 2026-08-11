package saml

import (
	"crypto/x509"
	"encoding/base64"
	"errors"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/malcolmston/passport"
)

// mustValidate fails the test unless the response validates.
func mustValidate(t *testing.T, s *Strategy, b64 string) *Assertion {
	t.Helper()
	a, err := s.Validate(b64)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	return a
}

// mustReject fails the test unless the response is rejected.
func mustReject(t *testing.T, s *Strategy, b64 string) error {
	t.Helper()
	a, err := s.Validate(b64)
	if err == nil {
		t.Fatalf("Validate accepted the response (NameID %q), want rejection", a.NameID)
	}
	return err
}

// TestValidSignedResponses covers the algorithm and placement combinations a
// real identity provider might produce.
func TestValidSignedResponses(t *testing.T) {
	rsaIdP := newTestIdP(t, "rsa")
	ecIdP := newTestIdP(t, "ecdsa")

	tests := []struct {
		name string
		mut  func(*fixture)
	}{
		{"rsa sha256 assertion signature exclusive c14n", func(f *fixture) {}},
		{"rsa sha512", func(f *fixture) { f.sigAlg = algRSASHA512; f.digestAlg = algDigestSHA512 }},
		{"rsa pss", func(f *fixture) { f.sigAlg = algRSAPSS256 }},
		{"ecdsa p256 sha256", func(f *fixture) { f.idp = ecIdP; f.sigAlg = algECDSASHA256 }},
		{"response level signature", func(f *fixture) { f.signTarget = "response" }},
		{"response and assertion both signed", func(f *fixture) { f.signTarget = "both" }},
		{"inclusive c14n", func(f *fixture) {
			f.c14nAlg = AlgC14N
			f.transforms = []string{AlgEnvelopedSignature, AlgC14N}
		}},
		{"c14n 1.1", func(f *fixture) {
			f.c14nAlg = AlgC14N11
			f.transforms = []string{AlgEnvelopedSignature, AlgC14N11}
		}},
		{"no explicit c14n transform defaults to c14n 1.0", func(f *fixture) {
			f.transforms = []string{AlgEnvelopedSignature}
		}},
		{"exclusive c14n with InclusiveNamespaces PrefixList", func(f *fixture) {
			f.prefixList = "samlp saml"
		}},
		{"embedded certificate matching the configured one", func(f *fixture) { f.embedCert = true }},
		{"idp initiated, no InResponseTo", func(f *fixture) { f.inResponseTo = "" }},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(rsaIdP)
			tc.mut(f)
			s := f.strategy()
			a := mustValidate(t, s, f.encode(t))
			if a.NameID != testNameID {
				t.Errorf("NameID = %q, want %q", a.NameID, testNameID)
			}
			if a.Issuer != testIssuer {
				t.Errorf("Issuer = %q, want %q", a.Issuer, testIssuer)
			}
			if a.ID != f.assertionID {
				t.Errorf("ID = %q, want %q", a.ID, f.assertionID)
			}
			if a.SessionIndex != "_session1" {
				t.Errorf("SessionIndex = %q", a.SessionIndex)
			}
			if a.InResponseTo != f.inResponseTo {
				t.Errorf("InResponseTo = %q, want %q", a.InResponseTo, f.inResponseTo)
			}
			wantResponseSigned := f.signTarget == "response" || f.signTarget == "both"
			if a.ResponseSigned != wantResponseSigned {
				t.Errorf("ResponseSigned = %v, want %v", a.ResponseSigned, wantResponseSigned)
			}
			if got := a.Attributes["groups"]; len(got) != 2 || got[0] != "staff" || got[1] != "admin" {
				t.Errorf("Attributes[groups] = %v, want [staff admin]", got)
			}
		})
	}
	_ = ecIdP
}

// TestUnsignedResponseRejected is the headline regression: before this change
// the package accepted any hand-written SAMLResponse. It must now be refused.
func TestUnsignedResponseRejected(t *testing.T) {
	f := newFixture(newTestIdP(t, "rsa"))
	f.signTarget = ""
	err := mustReject(t, f.strategy(), f.encode(t))
	if !errors.Is(err, ErrNoSignature) {
		t.Errorf("err = %v, want ErrNoSignature", err)
	}

	// The minimal forgery the old implementation accepted: a bare document
	// with nothing but a NameID in it.
	forged := base64.StdEncoding.EncodeToString([]byte(
		`<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"` +
			` xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"><saml:Assertion>` +
			`<saml:Subject><saml:NameID>attacker@evil.example</saml:NameID></saml:Subject>` +
			`</saml:Assertion></samlp:Response>`))
	mustReject(t, f.strategy(), forged)
}

// TestLegacyExtractNameIDIsForgeable pins the behaviour this change replaced.
//
// ExtractNameID is byte-for-byte the logic the package's Authenticate used to
// run, and it is still reachable through InsecureSkipSignatureValidation. The
// assertions below show what the old strategy did with each attack payload: it
// returned the attacker's subject. Every one of these is now rejected by
// Strategy.Validate, which is what the other tests in this file check.
func TestLegacyExtractNameIDIsForgeable(t *testing.T) {
	const forged = "attacker@evil.example"
	payloads := map[string]string{
		"wholly fabricated document": `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"` +
			` xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"><saml:Assertion><saml:Subject>` +
			`<saml:NameID>` + forged + `</saml:NameID></saml:Subject></saml:Assertion></samlp:Response>`,
		"no namespaces at all": `<Response><NameID>` + forged + `</NameID></Response>`,
		"NameID outside any assertion": `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"` +
			` xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"><saml:NameID>` + forged +
			`</saml:NameID><saml:Assertion/></samlp:Response>`,
	}
	for name, doc := range payloads {
		t.Run(name, func(t *testing.T) {
			b64 := base64.StdEncoding.EncodeToString([]byte(doc))

			got, err := ExtractNameID(b64)
			if err != nil || got != forged {
				t.Fatalf("ExtractNameID = %q, %v; want %q (the old, forgeable behaviour)", got, err, forged)
			}

			// The same input through the validating path.
			f := newFixture(newTestIdP(t, "rsa"))
			mustReject(t, f.strategy(), b64)
		})
	}
}

// TestWrongKeyRejected signs with a key the service provider does not trust.
func TestWrongKeyRejected(t *testing.T) {
	good := newTestIdP(t, "rsa")
	attacker := newTestIdP(t, "rsa")

	f := newFixture(attacker) // signed entirely by the attacker's key
	s := New(Options{
		IdPCertificates:             []*x509.Certificate{good.cert},
		Audience:                    testAudience,
		AssertionConsumerServiceURL: testACS,
		Clock:                       func() time.Time { return testNow },
	})
	err := mustReject(t, s, f.encode(t))
	if !errors.Is(err, ErrSignatureInvalid) {
		t.Errorf("err = %v, want ErrSignatureInvalid", err)
	}

	// Same document structure, but the SignatureValue is produced with a
	// foreign key while the embedded certificate is the genuine one.
	f2 := newFixture(good)
	f2.embedCert = true
	f2.signWith = attacker.key
	mustReject(t, f2.strategy(), f2.encode(t))
}

// TestEmbeddedCertificateNotTrustedOnItsOwn is the core trust rule: a
// certificate carried by the response is worthless unless it matches one that
// was configured out of band.
func TestEmbeddedCertificateNotTrustedOnItsOwn(t *testing.T) {
	good := newTestIdP(t, "rsa")
	attacker := newTestIdP(t, "rsa")

	// A fully self-consistent response: signed by the attacker's key and
	// carrying the attacker's certificate.
	f := newFixture(attacker)
	f.embedCert = true
	s := New(Options{
		IdPCertificates:             []*x509.Certificate{good.cert},
		Audience:                    testAudience,
		AssertionConsumerServiceURL: testACS,
		Clock:                       func() time.Time { return testNow },
	})
	err := mustReject(t, s, f.encode(t))
	if !errors.Is(err, ErrUntrustedCertificate) {
		t.Errorf("err = %v, want ErrUntrustedCertificate", err)
	}
}

// TestTamperedNameIDRejected changes the subject after signing.
func TestTamperedNameIDRejected(t *testing.T) {
	f := newFixture(newTestIdP(t, "rsa"))
	f.postSign = func(doc string) string {
		return strings.Replace(doc, testNameID+"</saml:NameID>", "attacker@evil.example</saml:NameID>", 1)
	}
	err := mustReject(t, f.strategy(), f.encode(t))
	if !errors.Is(err, ErrSignatureInvalid) {
		t.Errorf("err = %v, want ErrSignatureInvalid (digest mismatch)", err)
	}
}

// TestSignatureWrapping covers the XML Signature Wrapping family: a document
// that keeps a genuinely signed assertion while adding, relocating or
// duplicating one the attacker controls.
func TestSignatureWrapping(t *testing.T) {
	const forgedNameID = "attacker@evil.example"

	forgedAssertion := func(id string) string {
		return `<saml:Assertion ID="` + id + `" Version="2.0" IssueInstant="` + iso(testNow) + `">` +
			`<saml:Issuer>` + testIssuer + `</saml:Issuer>` +
			`<saml:Subject><saml:NameID>` + forgedNameID + `</saml:NameID>` +
			`<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">` +
			`<saml:SubjectConfirmationData Recipient="` + testACS + `" NotOnOrAfter="` + iso(testNow.Add(5*time.Minute)) + `"/>` +
			`</saml:SubjectConfirmation></saml:Subject>` +
			`<saml:Conditions NotBefore="` + iso(testNow.Add(-5*time.Minute)) + `" NotOnOrAfter="` + iso(testNow.Add(5*time.Minute)) + `">` +
			`<saml:AudienceRestriction><saml:Audience>` + testAudience + `</saml:Audience></saml:AudienceRestriction>` +
			`</saml:Conditions></saml:Assertion>`
	}

	tests := []struct {
		name     string
		postSign func(string) string
	}{
		{
			// Forged assertion placed before the signed one.
			name: "forged assertion before the signed assertion",
			postSign: func(doc string) string {
				return strings.Replace(doc, `<saml:Assertion ID="_assertion1"`,
					forgedAssertion("_forged")+`<saml:Assertion ID="_assertion1"`, 1)
			},
		},
		{
			// Forged assertion placed after the signed one.
			name: "forged assertion after the signed assertion",
			postSign: func(doc string) string {
				return strings.Replace(doc, `</saml:Assertion>`,
					`</saml:Assertion>`+forgedAssertion("_forged"), 1)
			},
		},
		{
			// The classic wrapping attack: the forged assertion is hidden
			// inside the ds:Signature itself, which the enveloped-signature
			// transform removes from the digest. The signature therefore
			// still verifies and only a structural rule can catch this.
			name: "forged assertion hidden inside the signature's ds:Object",
			postSign: func(doc string) string {
				return strings.Replace(doc, `</ds:Signature>`,
					`<ds:Object>`+forgedAssertion("_forged")+`</ds:Object></ds:Signature>`, 1)
			},
		},
		{
			// Forged assertion nested inside the signed assertion.
			name: "forged assertion nested inside the signed assertion",
			postSign: func(doc string) string {
				return strings.Replace(doc, `</saml:AttributeStatement>`,
					`</saml:AttributeStatement>`+forgedAssertion("_forged"), 1)
			},
		},
		{
			// The forged assertion reuses the signed assertion's ID so that
			// the ds:Reference could resolve to either.
			name: "forged assertion reusing the signed assertion's ID",
			postSign: func(doc string) string {
				return strings.Replace(doc, `<saml:Assertion ID="_assertion1"`,
					forgedAssertion("_assertion1")+`<saml:Assertion ID="_assertion1"`, 1)
			},
		},
		{
			// The signed assertion is moved out of the way into an
			// unreferenced samlp:Extensions element and a forged one takes
			// its place at the position an SP would read from.
			name: "signed assertion relocated into samlp:Extensions",
			postSign: func(doc string) string {
				start := strings.Index(doc, `<saml:Assertion ID="_assertion1"`)
				end := strings.Index(doc, `</saml:Assertion>`)
				if start < 0 || end < 0 {
					return doc
				}
				signed := doc[start : end+len(`</saml:Assertion>`)]
				rest := doc[:start] + forgedAssertion("_forged") + doc[end+len(`</saml:Assertion>`):]
				return strings.Replace(rest, `<samlp:Status>`,
					`<samlp:Extensions>`+signed+`</samlp:Extensions><samlp:Status>`, 1)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(newTestIdP(t, "rsa"))
			f.postSign = tc.postSign
			b64 := f.encode(t)

			a, err := f.strategy().Validate(b64)
			if err == nil {
				if a.NameID == forgedNameID {
					t.Fatalf("AUTHENTICATED AS THE FORGED SUBJECT %q", forgedNameID)
				}
				t.Fatalf("accepted a wrapped document (as %q), want rejection", a.NameID)
			}
		})
	}
}

// TestTimingConditions checks the assertion validity window and the clock skew.
func TestTimingConditions(t *testing.T) {
	idp := newTestIdP(t, "rsa")

	tests := []struct {
		name    string
		mut     func(*fixture)
		clock   time.Time
		skew    time.Duration
		wantErr bool
	}{
		{"inside the window", func(f *fixture) {}, testNow, 0, false},
		{
			name:    "expired",
			mut:     func(f *fixture) { f.notOnOrAfter = testNow.Add(-10 * time.Minute) },
			clock:   testNow,
			wantErr: true,
		},
		{
			name:    "not yet valid",
			mut:     func(f *fixture) { f.notBefore = testNow.Add(10 * time.Minute) },
			clock:   testNow,
			wantErr: true,
		},
		{
			// 30s past NotOnOrAfter, inside the default one minute skew.
			name:    "just expired but within the default skew",
			mut:     func(f *fixture) { f.notOnOrAfter = testNow.Add(-30 * time.Second) },
			clock:   testNow,
			wantErr: false,
		},
		{
			// 30s before NotBefore, inside the default skew.
			name:    "just early but within the default skew",
			mut:     func(f *fixture) { f.notBefore = testNow.Add(30 * time.Second) },
			clock:   testNow,
			wantErr: false,
		},
		{
			name:    "just expired with skew disabled",
			mut:     func(f *fixture) { f.notOnOrAfter = testNow.Add(-1 * time.Second) },
			clock:   testNow,
			skew:    -1,
			wantErr: true,
		},
		{
			name:    "exactly at NotOnOrAfter is expired, skew disabled",
			mut:     func(f *fixture) { f.notOnOrAfter = testNow },
			clock:   testNow,
			skew:    -1,
			wantErr: true,
		},
		{
			name:    "exactly at NotBefore is valid, skew disabled",
			mut:     func(f *fixture) { f.notBefore = testNow; f.notOnOrAfter = testNow.Add(time.Hour) },
			clock:   testNow,
			skew:    -1,
			wantErr: false,
		},
		{
			name:    "missing Conditions",
			mut:     func(f *fixture) { f.notBefore, f.notOnOrAfter = time.Time{}, time.Time{} },
			clock:   testNow,
			wantErr: false, // Conditions is still present, just unbounded
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(idp)
			tc.mut(f)
			clock := tc.clock
			s := f.strategy(func(o *Options) {
				o.Clock = func() time.Time { return clock }
				o.ClockSkew = tc.skew
			})
			_, err := s.Validate(f.encode(t))
			if tc.wantErr && err == nil {
				t.Fatal("Validate accepted the response, want rejection")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("Validate: %v", err)
			}
			if tc.wantErr && !errors.Is(err, ErrConditions) {
				t.Errorf("err = %v, want ErrConditions", err)
			}
		})
	}
}

// TestAudienceAndRecipient checks the audience, recipient and destination
// restrictions, including the fail-closed behaviour when they cannot be
// checked at all.
func TestAudienceAndRecipient(t *testing.T) {
	idp := newTestIdP(t, "rsa")

	t.Run("wrong audience", func(t *testing.T) {
		f := newFixture(idp)
		f.audience = "https://someone-else.example.com/metadata"
		if err := mustReject(t, f.strategy(), f.encode(t)); !errors.Is(err, ErrConditions) {
			t.Errorf("err = %v, want ErrConditions", err)
		}
	})

	t.Run("no audience configured", func(t *testing.T) {
		f := newFixture(idp)
		mustReject(t, f.strategy(func(o *Options) { o.Audience = "" }), f.encode(t))
	})

	t.Run("empty audience in the assertion", func(t *testing.T) {
		f := newFixture(idp)
		f.audience = "" // renders an empty <saml:Audience></saml:Audience>
		mustReject(t, f.strategy(), f.encode(t))
	})

	t.Run("no AudienceRestriction at all", func(t *testing.T) {
		f := newFixture(idp)
		f.postSign = func(doc string) string {
			start := strings.Index(doc, "<saml:AudienceRestriction>")
			end := strings.Index(doc, "</saml:AudienceRestriction>")
			if start < 0 || end < 0 {
				return doc
			}
			return doc[:start] + doc[end+len("</saml:AudienceRestriction>"):]
		}
		// Removing it also breaks the digest; both are rejections, and the
		// point here is that an assertion without an audience restriction
		// can never be accepted.
		mustReject(t, f.strategy(), f.encode(t))
	})

	t.Run("wrong recipient", func(t *testing.T) {
		f := newFixture(idp)
		f.recipient = "https://evil.example.com/acs"
		f.destination = ""
		if err := mustReject(t, f.strategy(), f.encode(t)); !errors.Is(err, ErrConditions) {
			t.Errorf("err = %v, want ErrConditions", err)
		}
	})

	t.Run("wrong destination", func(t *testing.T) {
		f := newFixture(idp)
		f.destination = "https://evil.example.com/acs"
		f.recipient = ""
		if err := mustReject(t, f.strategy(), f.encode(t)); !errors.Is(err, ErrConditions) {
			t.Errorf("err = %v, want ErrConditions", err)
		}
	})

	t.Run("recipient present but no ACS URL configured", func(t *testing.T) {
		f := newFixture(idp)
		mustReject(t, f.strategy(func(o *Options) { o.AssertionConsumerServiceURL = "" }), f.encode(t))
	})
}

// TestInResponseTo exercises the optional request-ID validator.
func TestInResponseTo(t *testing.T) {
	idp := newTestIdP(t, "rsa")

	t.Run("accepted", func(t *testing.T) {
		f := newFixture(idp)
		s := f.strategy(func(o *Options) {
			o.ValidateInResponseTo = func(id string) bool { return id == "_request1" }
		})
		mustValidate(t, s, f.encode(t))
	})

	t.Run("rejected", func(t *testing.T) {
		f := newFixture(idp)
		f.inResponseTo = "_someone-elses-request"
		s := f.strategy(func(o *Options) {
			o.ValidateInResponseTo = func(id string) bool { return id == "_request1" }
		})
		mustReject(t, s, f.encode(t))
	})

	t.Run("idp initiated rejected when a request is required", func(t *testing.T) {
		f := newFixture(idp)
		f.inResponseTo = ""
		s := f.strategy(func(o *Options) {
			o.ValidateInResponseTo = func(id string) bool { return id != "" }
		})
		mustReject(t, s, f.encode(t))
	})
}

// TestReplayRejected checks that the same assertion cannot be used twice.
func TestReplayRejected(t *testing.T) {
	f := newFixture(newTestIdP(t, "rsa"))
	s := f.strategy()
	b64 := f.encode(t)

	mustValidate(t, s, b64)
	err := mustReject(t, s, b64)
	if !errors.Is(err, ErrReplay) {
		t.Errorf("err = %v, want ErrReplay", err)
	}

	// A second strategy has its own cache, so the same response is fresh
	// there. This documents that replay protection is per ReplayCache.
	mustValidate(t, f.strategy(), b64)
}

// TestStatusCodeRejected refuses anything but Success.
func TestStatusCodeRejected(t *testing.T) {
	for _, code := range []string{
		"urn:oasis:names:tc:SAML:2.0:status:Requester",
		"urn:oasis:names:tc:SAML:2.0:status:Responder",
		"urn:oasis:names:tc:SAML:2.0:status:AuthnFailed",
		"",
	} {
		f := newFixture(newTestIdP(t, "rsa"))
		f.statusCode = code
		// Sign the whole response so the status is inside the signature and
		// the rejection cannot be attributed to a broken digest.
		f.signTarget = "response"
		err := mustReject(t, f.strategy(), f.encode(t))
		if !errors.Is(err, ErrStatus) {
			t.Errorf("status %q: err = %v, want ErrStatus", code, err)
		}
	}
}

// TestDoctypeRejected covers XXE and entity-expansion payloads.
func TestDoctypeRejected(t *testing.T) {
	f := newFixture(newTestIdP(t, "rsa"))
	signed := f.xml(t)

	payloads := map[string]string{
		"external entity": `<!DOCTYPE samlp:Response [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>`,
		"billion laughs": `<!DOCTYPE samlp:Response [` +
			`<!ENTITY lol "lol">` +
			`<!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">` +
			`<!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">]>`,
		"external dtd": `<!DOCTYPE samlp:Response SYSTEM "http://evil.example.com/x.dtd">`,
	}
	for name, doctype := range payloads {
		t.Run(name, func(t *testing.T) {
			b64 := base64.StdEncoding.EncodeToString([]byte(doctype + signed))
			err := mustReject(t, f.strategy(), b64)
			if !errors.Is(err, ErrDoctype) {
				t.Errorf("err = %v, want ErrDoctype", err)
			}
		})
	}

	t.Run("undefined entity reference in content", func(t *testing.T) {
		doc := strings.Replace(signed, testNameID, "&xxe;", 1)
		mustReject(t, f.strategy(), base64.StdEncoding.EncodeToString([]byte(doc)))
	})
}

// TestSHA1 checks that SHA-1 is refused by default and only accepted behind the
// explicit opt-in.
func TestSHA1(t *testing.T) {
	idp := newTestIdP(t, "rsa")

	t.Run("sha1 signature rejected by default", func(t *testing.T) {
		f := newFixture(idp)
		f.sigAlg = algRSASHA1
		f.digestAlg = algDigestSHA1
		if err := mustReject(t, f.strategy(), f.encode(t)); !errors.Is(err, ErrWeakAlgorithm) {
			t.Errorf("err = %v, want ErrWeakAlgorithm", err)
		}
	})

	t.Run("sha1 digest alone rejected by default", func(t *testing.T) {
		f := newFixture(idp)
		f.digestAlg = algDigestSHA1
		if err := mustReject(t, f.strategy(), f.encode(t)); !errors.Is(err, ErrWeakAlgorithm) {
			t.Errorf("err = %v, want ErrWeakAlgorithm", err)
		}
	})

	t.Run("sha1 accepted with AllowSHA1", func(t *testing.T) {
		f := newFixture(idp)
		f.sigAlg = algRSASHA1
		f.digestAlg = algDigestSHA1
		s := f.strategy(func(o *Options) { o.AllowSHA1 = true })
		mustValidate(t, s, f.encode(t))
	})
}

// TestTransformsRejected checks the transform allow-list. XPath and XSLT are
// the dangerous ones: they turn signature validation into an interpreter.
func TestTransformsRejected(t *testing.T) {
	idp := newTestIdP(t, "rsa")

	for _, tr := range []string{
		"http://www.w3.org/TR/1999/REC-xslt-19991116",
		"http://www.w3.org/TR/1999/REC-xpath-19991116",
		"http://www.w3.org/2002/06/xmldsig-filter2",
		"http://www.w3.org/2000/09/xmldsig#base64",
		// c14nModeFor understands this one, but referenceTransforms
		// allow-lists only the comment-free canonicalization URIs, so it is
		// still refused as a reference transform.
		"http://www.w3.org/2001/10/xml-exc-c14n#WithComments",
		"http://www.w3.org/2010/xml-c14n2",
	} {
		t.Run(tr, func(t *testing.T) {
			f := newFixture(idp)
			f.transforms = []string{AlgEnvelopedSignature, AlgC14NExclusive, tr}
			mustReject(t, f.strategy(), f.encode(t))
		})
	}

	t.Run("missing enveloped-signature transform", func(t *testing.T) {
		f := newFixture(idp)
		f.transforms = []string{AlgC14NExclusive}
		mustReject(t, f.strategy(), f.encode(t))
	})

	// The "#WithComments" canonicalization algorithms used to appear here;
	// they are supported now, and TestVerifySignatureWithCommentsCanonicalization
	// covers them. An algorithm the package does not implement is still a
	// rejection rather than an approximation.
	t.Run("unsupported SignedInfo canonicalization", func(t *testing.T) {
		f := newFixture(idp)
		f.c14nAlg = "http://www.w3.org/2010/xml-c14n2"
		mustReject(t, f.strategy(), f.encode(t))
	})
}

// TestNoCertificateRejectsEverything is the fail-closed rule: without a
// configured certificate nothing authenticates, including a perfectly valid
// response.
func TestNoCertificateRejectsEverything(t *testing.T) {
	f := newFixture(newTestIdP(t, "rsa"))
	b64 := f.encode(t)

	s := New(Options{Audience: testAudience, AssertionConsumerServiceURL: testACS,
		Clock: func() time.Time { return testNow }})
	if err := mustReject(t, s, b64); !errors.Is(err, ErrNoCertificates) {
		t.Errorf("err = %v, want ErrNoCertificates", err)
	}

	// And through the strategy entry point.
	c := &passport.Context{}
	s.Authenticate(c, postForm(url.Values{"SAMLResponse": {b64}}))
	if c.Result() != passport.ResultFail {
		t.Errorf("Authenticate result = %v, want ResultFail", c.Result())
	}
}

// TestSignaturePlacement rejects signatures that do not envelop what they
// reference.
func TestSignaturePlacement(t *testing.T) {
	idp := newTestIdP(t, "rsa")

	t.Run("signature moved out of the element it references", func(t *testing.T) {
		f := newFixture(idp)
		f.postSign = func(doc string) string {
			start := strings.Index(doc, `<ds:Signature`)
			end := strings.Index(doc, `</ds:Signature>`) + len(`</ds:Signature>`)
			if start < 0 || end < len(`</ds:Signature>`) {
				return doc
			}
			sig := doc[start:end]
			doc = doc[:start] + doc[end:]
			// Re-attach it as a child of the response instead.
			return strings.Replace(doc, `<samlp:Status>`, sig+`<samlp:Status>`, 1)
		}
		mustReject(t, f.strategy(), f.encode(t))
	})

	t.Run("second forged signature elsewhere in the document", func(t *testing.T) {
		f := newFixture(idp)
		f.postSign = func(doc string) string {
			return strings.Replace(doc, `<samlp:Status>`,
				`<ds:Signature xmlns:ds="`+nsDSig+`"><ds:SignedInfo>`+
					`<ds:CanonicalizationMethod Algorithm="`+AlgC14NExclusive+`"/>`+
					`<ds:SignatureMethod Algorithm="`+algRSASHA256+`"/>`+
					`<ds:Reference URI="#_assertion1"><ds:Transforms>`+
					`<ds:Transform Algorithm="`+AlgEnvelopedSignature+`"/>`+
					`<ds:Transform Algorithm="`+AlgC14NExclusive+`"/></ds:Transforms>`+
					`<ds:DigestMethod Algorithm="`+algDigestSHA256+`"/>`+
					`<ds:DigestValue>AAAA</ds:DigestValue></ds:Reference></ds:SignedInfo>`+
					`<ds:SignatureValue>AAAA</ds:SignatureValue></ds:Signature><samlp:Status>`, 1)
		}
		mustReject(t, f.strategy(), f.encode(t))
	})
}

// TestEncryptedAssertionRejected: with no SP decryption key configured,
// encrypted content must mean rejected, not ignored. See xmlenc_test.go for the
// configured-key cases.
func TestEncryptedAssertionRejected(t *testing.T) {
	f := newFixture(newTestIdP(t, "rsa"))
	f.postSign = func(doc string) string {
		return strings.Replace(doc, `<samlp:Status>`,
			`<saml:EncryptedAssertion><saml:X/></saml:EncryptedAssertion><samlp:Status>`, 1)
	}
	if err := mustReject(t, f.strategy(), f.encode(t)); !errors.Is(err, ErrEncrypted) {
		t.Errorf("err = %v, want ErrEncrypted", err)
	}
}

// TestSizeLimit refuses an oversized response before parsing it.
func TestSizeLimit(t *testing.T) {
	f := newFixture(newTestIdP(t, "rsa"))
	s := f.strategy(func(o *Options) { o.MaxResponseBytes = 128 })
	if err := mustReject(t, s, f.encode(t)); !errors.Is(err, ErrTooLarge) {
		t.Errorf("err = %v, want ErrTooLarge", err)
	}
}

// TestDepthLimit refuses a deeply nested document.
func TestDepthLimit(t *testing.T) {
	f := newFixture(newTestIdP(t, "rsa"))
	f.postSign = func(doc string) string {
		return strings.Replace(doc, `<samlp:Status>`,
			strings.Repeat(`<samlp:Deep>`, 40)+strings.Repeat(`</samlp:Deep>`, 40)+`<samlp:Status>`, 1)
	}
	s := f.strategy(func(o *Options) { o.MaxDepth = 10 })
	mustReject(t, s, f.encode(t))
}

// TestPEMConfiguration exercises Options.IdPCertificatePEM and the fail-closed
// handling of a bad configuration.
func TestPEMConfiguration(t *testing.T) {
	f := newFixture(newTestIdP(t, "rsa"))
	pemBytes := certPEM(f.idp.cert.Raw)

	s := New(Options{
		IdPCertificatePEM:           pemBytes,
		Audience:                    testAudience,
		AssertionConsumerServiceURL: testACS,
		Clock:                       func() time.Time { return testNow },
	})
	if err := s.ConfigError(); err != nil {
		t.Fatalf("ConfigError: %v", err)
	}
	mustValidate(t, s, f.encode(t))

	bad := New(Options{IdPCertificatePEM: []byte("-----BEGIN CERTIFICATE-----\nnot base64\n-----END CERTIFICATE-----\n")})
	if bad.ConfigError() == nil {
		t.Fatal("ConfigError = nil for an unparsable PEM, want an error")
	}
	c := &passport.Context{}
	bad.Authenticate(c, postForm(url.Values{"SAMLResponse": {f.encode(t)}}))
	if c.Result() != passport.ResultError {
		t.Errorf("Authenticate result = %v, want ResultError", c.Result())
	}
}

func certPEM(der []byte) []byte {
	var b strings.Builder
	b.WriteString("-----BEGIN CERTIFICATE-----\n")
	enc := base64.StdEncoding.EncodeToString(der)
	for len(enc) > 64 {
		b.WriteString(enc[:64] + "\n")
		enc = enc[64:]
	}
	b.WriteString(enc + "\n-----END CERTIFICATE-----\n")
	return []byte(b.String())
}

// TestInsecureSkipSignatureValidation documents the escape hatch: off by
// default, and when on it really does accept anything.
func TestInsecureSkipSignatureValidation(t *testing.T) {
	forged := base64.StdEncoding.EncodeToString([]byte(
		`<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"` +
			` xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"><saml:Assertion><saml:Subject>` +
			`<saml:NameID>anyone@example.com</saml:NameID></saml:Subject></saml:Assertion></samlp:Response>`))

	if _, err := New(Options{}).Validate(forged); err == nil {
		t.Fatal("the default configuration accepted an unsigned response")
	}

	s := New(Options{InsecureSkipSignatureValidation: true})
	a, err := s.Validate(forged)
	if err != nil {
		t.Fatalf("Validate with the escape hatch: %v", err)
	}
	if a.NameID != "anyone@example.com" {
		t.Errorf("NameID = %q", a.NameID)
	}
}

// TestVerifyAssertionHook checks the richer verify callback.
func TestVerifyAssertionHook(t *testing.T) {
	f := newFixture(newTestIdP(t, "rsa"))
	var seen *Assertion
	s := f.strategy(func(o *Options) {
		o.VerifyAssertion = func(a *Assertion) (any, error) {
			seen = a
			return map[string]string{"email": a.NameID}, nil
		}
	})
	c := &passport.Context{}
	s.Authenticate(c, postForm(url.Values{"SAMLResponse": {f.encode(t)}}))
	if c.Result() != passport.ResultSuccess {
		t.Fatalf("result = %v", c.Result())
	}
	if seen == nil || seen.Attributes["email"][0] != testNameID {
		t.Fatalf("assertion not passed through: %+v", seen)
	}
	if got := c.SuccessUser().(map[string]string)["email"]; got != testNameID {
		t.Errorf("user email = %q", got)
	}
}

// TestMemoryReplayCache covers the bound and the expiry-based eviction.
func TestMemoryReplayCache(t *testing.T) {
	now := testNow
	c := &MemoryReplayCache{MaxEntries: 2, Clock: func() time.Time { return now }}

	if fresh, err := c.Store("a", now.Add(time.Minute)); err != nil || !fresh {
		t.Fatalf("first Store: fresh=%v err=%v", fresh, err)
	}
	if fresh, err := c.Store("a", now.Add(time.Minute)); err != nil || fresh {
		t.Fatalf("replayed Store: fresh=%v err=%v", fresh, err)
	}
	if fresh, err := c.Store("b", now.Add(time.Minute)); err != nil || !fresh {
		t.Fatalf("second id: fresh=%v err=%v", fresh, err)
	}
	// Full: a third live entry must be refused rather than silently
	// displacing an existing one.
	if _, err := c.Store("c", now.Add(time.Minute)); !errors.Is(err, ErrReplayCacheFull) {
		t.Fatalf("full cache err = %v, want ErrReplayCacheFull", err)
	}
	// Once the first two lapse, the cache makes room again.
	now = now.Add(2 * time.Minute)
	if fresh, err := c.Store("c", now.Add(time.Minute)); err != nil || !fresh {
		t.Fatalf("after expiry: fresh=%v err=%v", fresh, err)
	}
	if c.Len() != 1 {
		t.Errorf("Len = %d, want 1 after eviction", c.Len())
	}
}

// TestMemoryReplayCacheConcurrent checks that exactly one caller wins the race
// for a given assertion ID.
func TestMemoryReplayCacheConcurrent(t *testing.T) {
	c := NewMemoryReplayCache(0)
	const n = 64
	var (
		wg    sync.WaitGroup
		mu    sync.Mutex
		wins  int
		errCh []error
	)
	expires := time.Now().Add(time.Minute)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			fresh, err := c.Store("same-id", expires)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				errCh = append(errCh, err)
			}
			if fresh {
				wins++
			}
		}()
	}
	wg.Wait()
	if len(errCh) != 0 {
		t.Fatalf("errors: %v", errCh)
	}
	if wins != 1 {
		t.Errorf("%d callers saw the ID as fresh, want exactly 1", wins)
	}
}

// TestStrategyRejectsNonResponseRoot checks the document shape.
func TestStrategyRejectsNonResponseRoot(t *testing.T) {
	f := newFixture(newTestIdP(t, "rsa"))
	f.postSign = func(doc string) string {
		doc = strings.Replace(doc, "<samlp:Response", "<samlp:Bogus", 1)
		return strings.Replace(doc, "</samlp:Response>", "</samlp:Bogus>", 1)
	}
	mustReject(t, f.strategy(), f.encode(t))
}
