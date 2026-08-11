package saml

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"
)

// This file builds XML Encryption fixtures programmatically, the same way
// fixture_test.go builds signed ones: the service provider's key pair is
// generated in-process and every ciphertext is produced here, so the suite is
// self-contained and needs no vendored blobs.
//
// The encryptor deliberately does *not* share code with the decryptor. It
// writes the wire format straight out of the XML Encryption specification, so a
// bug in xmlenc.go cannot hide behind a matching bug in the fixture builder.

// newTestSPKey generates a service provider decryption key.
func newTestSPKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating SP key: %v", err)
	}
	return key
}

// encryptor renders a saml:EncryptedAssertion or saml:EncryptedID around a
// plaintext XML fragment.
type encryptor struct {
	// pub is the public key the session key is wrapped to.
	pub *rsa.PublicKey

	// wrapper is the container's local name in the SAML assertion
	// namespace. Defaults to "EncryptedAssertion".
	wrapper string

	// contentAlg defaults to AES-256-GCM, keyAlg to RSA-OAEP-MGF1P.
	contentAlg string
	keyAlg     string

	// digestAlg is the ds:DigestMethod written inside the key
	// EncryptionMethod; "" omits it, which selects the SHA-1 default.
	digestAlg string
	// mgfAlg is the xenc11:MGF Algorithm, only meaningful for AlgRSAOAEP.
	mgfAlg string

	// keyAsSibling places the EncryptedKey next to the EncryptedData rather
	// than inside its ds:KeyInfo, as ADFS and Shibboleth do.
	keyAsSibling bool

	// mutateCiphertext corrupts the content ciphertext after encryption.
	mutateCiphertext func([]byte) []byte
}

// oaepHash resolves the hash the OAEP wrapping uses.
func (e *encryptor) oaepHash(t *testing.T) crypto.Hash {
	t.Helper()
	if e.digestAlg == "" {
		return crypto.SHA1
	}
	d, ok := digestAlgorithms[e.digestAlg]
	if !ok {
		t.Fatalf("unknown digest URI %q", e.digestAlg)
	}
	return d.hash
}

// encrypt returns the container element for plaintext.
func (e *encryptor) encrypt(t *testing.T, plaintext string) string {
	t.Helper()
	wrapper := e.wrapper
	if wrapper == "" {
		wrapper = "EncryptedAssertion"
	}
	contentAlg := e.contentAlg
	if contentAlg == "" {
		contentAlg = AlgAES256GCM
	}
	keyAlg := e.keyAlg
	if keyAlg == "" {
		keyAlg = AlgRSAOAEPMGF1P
	}
	alg, ok := contentAlgorithms[contentAlg]
	if !ok {
		t.Fatalf("unknown content algorithm %q", contentAlg)
	}

	sessionKey := make([]byte, alg.keyLen)
	if _, err := rand.Read(sessionKey); err != nil {
		t.Fatalf("rand: %v", err)
	}
	ciphertext := e.sealContent(t, alg, sessionKey, []byte(plaintext))
	if e.mutateCiphertext != nil {
		ciphertext = e.mutateCiphertext(ciphertext)
	}

	var wrapped []byte
	var err error
	switch keyAlg {
	case AlgRSAOAEPMGF1P, AlgRSAOAEP:
		h := e.oaepHash(t)
		fn, hErr := newHashConstructor(h)
		if hErr != nil {
			t.Fatalf("newHashConstructor: %v", hErr)
		}
		wrapped, err = rsa.EncryptOAEP(fn(), rand.Reader, e.pub, sessionKey, nil)
	case AlgRSA15:
		wrapped, err = rsa.EncryptPKCS1v15(rand.Reader, e.pub, sessionKey)
	default:
		t.Fatalf("unknown key transport algorithm %q", keyAlg)
	}
	if err != nil {
		t.Fatalf("wrapping session key: %v", err)
	}

	keyMethod := `<xenc:EncryptionMethod Algorithm="` + keyAlg + `">`
	if e.digestAlg != "" {
		keyMethod += `<ds:DigestMethod xmlns:ds="` + nsDSig + `" Algorithm="` + e.digestAlg + `"/>`
	}
	if e.mgfAlg != "" {
		keyMethod += `<xenc11:MGF xmlns:xenc11="` + nsXMLEnc11 + `" Algorithm="` + e.mgfAlg + `"/>`
	}
	keyMethod += `</xenc:EncryptionMethod>`

	encryptedKey := `<xenc:EncryptedKey xmlns:xenc="` + nsXMLEnc + `">` + keyMethod +
		`<xenc:CipherData><xenc:CipherValue>` +
		base64.StdEncoding.EncodeToString(wrapped) +
		`</xenc:CipherValue></xenc:CipherData></xenc:EncryptedKey>`

	keyInfo := `<ds:KeyInfo xmlns:ds="` + nsDSig + `">` + encryptedKey + `</ds:KeyInfo>`
	sibling := ""
	if e.keyAsSibling {
		keyInfo = ""
		sibling = encryptedKey
	}

	return `<saml:` + wrapper + ` xmlns:saml="` + nsSAMLAssertion + `">` +
		`<xenc:EncryptedData xmlns:xenc="` + nsXMLEnc + `" Type="` + nsXMLEnc + `Element">` +
		`<xenc:EncryptionMethod Algorithm="` + contentAlg + `"/>` +
		keyInfo +
		`<xenc:CipherData><xenc:CipherValue>` +
		base64.StdEncoding.EncodeToString(ciphertext) +
		`</xenc:CipherValue></xenc:CipherData>` +
		`</xenc:EncryptedData>` + sibling +
		`</saml:` + wrapper + `>`
}

// sealContent encrypts plaintext, prefixing the IV as XML Encryption requires.
func (e *encryptor) sealContent(t *testing.T, alg contentAlgorithm, key, plaintext []byte) []byte {
	t.Helper()
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatalf("aes.NewCipher: %v", err)
	}
	if alg.gcm {
		aead, err := cipher.NewGCM(block)
		if err != nil {
			t.Fatalf("cipher.NewGCM: %v", err)
		}
		nonce := make([]byte, aead.NonceSize())
		if _, err := rand.Read(nonce); err != nil {
			t.Fatalf("rand: %v", err)
		}
		return aead.Seal(nonce, nonce, plaintext, nil)
	}
	// AES-CBC with the ISO 10126 padding XML Encryption specifies: between 1
	// and blockSize bytes, the last of which is the padding length.
	bs := block.BlockSize()
	pad := bs - len(plaintext)%bs
	padded := make([]byte, len(plaintext)+pad)
	copy(padded, plaintext)
	if _, err := rand.Read(padded[len(plaintext) : len(padded)-1]); err != nil {
		t.Fatalf("rand: %v", err)
	}
	padded[len(padded)-1] = byte(pad)

	out := make([]byte, bs+len(padded))
	if _, err := rand.Read(out[:bs]); err != nil {
		t.Fatalf("rand: %v", err)
	}
	cipher.NewCBCEncrypter(block, out[:bs]).CryptBlocks(out[bs:], padded)
	return out
}

// spStrategy configures the fixture's strategy with an SP decryption key.
func spOption(key *rsa.PrivateKey) func(*Options) {
	return func(o *Options) { o.SPDecryptionKeys = []crypto.PrivateKey{key} }
}

// TestEncryptedAssertionAuthenticates covers the two coverage paths a decrypted
// assertion may take, across the algorithms the package accepts.
func TestEncryptedAssertionAuthenticates(t *testing.T) {
	idp := newTestIdP(t, "rsa")
	sp := newTestSPKey(t)

	cases := []struct {
		name string
		enc  encryptor
		// signTarget of the fixture: "response" exercises path 1 (the outer
		// signature covers the ciphertext), "assertion" exercises path 2
		// (the decrypted assertion signs itself).
		signTarget string
		options    []func(*Options)
	}{
		{"OAEP-MGF1P + AES-256-GCM, inner signature", encryptor{}, "assertion", nil},
		{"OAEP-MGF1P + AES-256-GCM, response signature", encryptor{}, "response", nil},
		{"OAEP-MGF1P + AES-128-GCM", encryptor{contentAlg: AlgAES128GCM}, "assertion", nil},
		{"OAEP-MGF1P + AES-192-GCM", encryptor{contentAlg: AlgAES192GCM}, "assertion", nil},
		{
			"OAEP-SHA256 + AES-256-GCM",
			encryptor{keyAlg: AlgRSAOAEP, digestAlg: algDigestSHA256, mgfAlg: nsXMLEnc11 + "mgf1sha256"},
			"assertion", nil,
		},
		{
			"OAEP-SHA256 with no explicit MGF",
			encryptor{keyAlg: AlgRSAOAEP, digestAlg: algDigestSHA256},
			"assertion", nil,
		},
		{"EncryptedKey beside the EncryptedData", encryptor{keyAsSibling: true}, "assertion", nil},
		{
			"AES-256-CBC when explicitly enabled",
			encryptor{contentAlg: AlgAES256CBC},
			"assertion",
			[]func(*Options){func(o *Options) { o.AllowCBCDecryption = true }},
		},
		{
			"RSA-1.5 when explicitly enabled",
			encryptor{keyAlg: AlgRSA15},
			"assertion",
			[]func(*Options){func(o *Options) { o.AllowRSA15 = true }},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			enc := tc.enc
			enc.pub = &sp.PublicKey
			f := newFixture(idp)
			f.signTarget = tc.signTarget
			f.encrypt = enc.encrypt

			opts := append([]func(*Options){spOption(sp)}, tc.options...)
			a := mustValidate(t, f.strategy(opts...), f.encode(t))
			if a.NameID != testNameID {
				t.Errorf("NameID = %q, want %q", a.NameID, testNameID)
			}
			if !a.Encrypted {
				t.Error("Assertion.Encrypted = false, want true")
			}
			if a.SessionIndex != "_session1" {
				t.Errorf("SessionIndex = %q, want _session1", a.SessionIndex)
			}
			if got := a.Attributes["groups"]; len(got) != 2 {
				t.Errorf("groups attribute = %v, want two values", got)
			}
		})
	}
}

// TestEncryptedAssertionWithoutSignature is the whole point of the feature:
// decryption is not authentication. A perfectly well-formed assertion,
// encrypted to the SP's real public key by someone who is not the IdP, must not
// authenticate anybody.
func TestEncryptedAssertionWithoutSignature(t *testing.T) {
	idp := newTestIdP(t, "rsa")
	sp := newTestSPKey(t)
	enc := encryptor{pub: &sp.PublicKey}

	f := newFixture(idp)
	f.signTarget = "" // no signature anywhere in the document
	f.encrypt = enc.encrypt

	err := mustReject(t, f.strategy(spOption(sp)), f.encode(t))
	if !errors.Is(err, ErrNoSignature) {
		t.Errorf("err = %v, want ErrNoSignature", err)
	}
}

// TestEncryptedAssertionForgedPlaintext is the same attack in its realistic
// form: the attacker takes a genuine response, throws the ciphertext away and
// encrypts their own assertion to the SP's published public key.
func TestEncryptedAssertionForgedPlaintext(t *testing.T) {
	idp := newTestIdP(t, "rsa")
	sp := newTestSPKey(t)
	enc := encryptor{pub: &sp.PublicKey}

	f := newFixture(idp)
	f.signTarget = "assertion"
	f.encrypt = func(t *testing.T, assertionXML string) string {
		// Strip the IdP's signature and rename the subject.
		start := strings.Index(assertionXML, `<ds:Signature`)
		end := strings.Index(assertionXML, `</ds:Signature>`) + len(`</ds:Signature>`)
		forged := assertionXML[:start] + assertionXML[end:]
		forged = strings.ReplaceAll(forged, testNameID, "attacker@evil.example")
		return enc.encrypt(t, forged)
	}
	err := mustReject(t, f.strategy(spOption(sp)), f.encode(t))
	if !errors.Is(err, ErrNoSignature) {
		t.Errorf("err = %v, want ErrNoSignature", err)
	}
}

// TestEncryptedAssertionTampered corrupts the ciphertext of an assertion the
// response signature does not cover.
func TestEncryptedAssertionTampered(t *testing.T) {
	idp := newTestIdP(t, "rsa")
	sp := newTestSPKey(t)

	t.Run("GCM tag rejects a flipped bit", func(t *testing.T) {
		enc := encryptor{pub: &sp.PublicKey, mutateCiphertext: func(b []byte) []byte {
			out := append([]byte(nil), b...)
			out[len(out)/2] ^= 0x01
			return out
		}}
		f := newFixture(idp)
		f.encrypt = enc.encrypt
		if err := mustReject(t, f.strategy(spOption(sp)), f.encode(t)); !errors.Is(err, ErrDecryptFailed) {
			t.Errorf("err = %v, want ErrDecryptFailed", err)
		}
	})

	t.Run("CBC failure is indistinguishable", func(t *testing.T) {
		enc := encryptor{pub: &sp.PublicKey, contentAlg: AlgAES256CBC,
			mutateCiphertext: func(b []byte) []byte {
				out := append([]byte(nil), b...)
				out[len(out)/2] ^= 0x01
				return out
			}}
		f := newFixture(idp)
		f.encrypt = enc.encrypt
		err := mustReject(t, f.strategy(spOption(sp),
			func(o *Options) { o.AllowCBCDecryption = true }), f.encode(t))
		if !errors.Is(err, ErrDecryptFailed) {
			t.Errorf("err = %v, want ErrDecryptFailed", err)
		}
		// The message must not describe what went wrong; that is the whole
		// mitigation against a padding oracle.
		if got := err.Error(); got != ErrDecryptFailed.Error() {
			t.Errorf("err.Error() = %q, want the generic %q", got, ErrDecryptFailed.Error())
		}
	})
}

// TestEncryptedAssertionTamperedInsideResponseSignature: with the outer
// signature in place, touching the ciphertext breaks the response digest.
func TestEncryptedAssertionTamperedUnderResponseSignature(t *testing.T) {
	idp := newTestIdP(t, "rsa")
	sp := newTestSPKey(t)
	enc := encryptor{pub: &sp.PublicKey}

	f := newFixture(idp)
	f.signTarget = "response"
	f.encrypt = enc.encrypt
	f.postSign = func(doc string) string {
		i := strings.Index(doc, `<xenc:CipherValue>`)
		if i < 0 {
			t.Fatal("no CipherValue in fixture")
		}
		j := i + len(`<xenc:CipherValue>`)
		// Swap two adjacent base64 characters, keeping the length intact.
		return doc[:j] + swapTwo(doc[j:j+8]) + doc[j+8:]
	}
	if err := mustReject(t, f.strategy(spOption(sp)), f.encode(t)); !errors.Is(err, ErrSignatureInvalid) {
		t.Errorf("err = %v, want ErrSignatureInvalid", err)
	}
}

func swapTwo(s string) string {
	b := []byte(s)
	if b[0] == b[1] {
		b[0] = 'A'
		if b[1] == 'A' {
			b[0] = 'B'
		}
		return string(b)
	}
	b[0], b[1] = b[1], b[0]
	return string(b)
}

// TestEncryptedAssertionKeyHandling covers the key-configuration failure modes.
func TestEncryptedAssertionKeyHandling(t *testing.T) {
	idp := newTestIdP(t, "rsa")
	sp := newTestSPKey(t)
	other := newTestSPKey(t)

	t.Run("no SP key configured", func(t *testing.T) {
		enc := encryptor{pub: &sp.PublicKey}
		f := newFixture(idp)
		f.encrypt = enc.encrypt
		err := mustReject(t, f.strategy(), f.encode(t))
		if !errors.Is(err, ErrNoDecryptionKey) {
			t.Errorf("err = %v, want ErrNoDecryptionKey", err)
		}
		if !errors.Is(err, ErrEncrypted) {
			t.Errorf("err = %v, want it to wrap ErrEncrypted", err)
		}
	})

	t.Run("wrong SP key configured", func(t *testing.T) {
		enc := encryptor{pub: &other.PublicKey}
		f := newFixture(idp)
		f.encrypt = enc.encrypt
		if err := mustReject(t, f.strategy(spOption(sp)), f.encode(t)); !errors.Is(err, ErrDecryptFailed) {
			t.Errorf("err = %v, want ErrDecryptFailed", err)
		}
	})

	t.Run("one of several keys matches", func(t *testing.T) {
		enc := encryptor{pub: &sp.PublicKey}
		f := newFixture(idp)
		f.encrypt = enc.encrypt
		s := f.strategy(func(o *Options) {
			o.SPDecryptionKeys = []crypto.PrivateKey{other, sp}
		})
		if a := mustValidate(t, s, f.encode(t)); a.NameID != testNameID {
			t.Errorf("NameID = %q", a.NameID)
		}
	})

	t.Run("PEM configuration", func(t *testing.T) {
		enc := encryptor{pub: &sp.PublicKey}
		f := newFixture(idp)
		f.encrypt = enc.encrypt
		s := f.strategy(func(o *Options) { o.SPDecryptionKeyPEM = keyPEM(t, sp) })
		if err := s.ConfigError(); err != nil {
			t.Fatalf("ConfigError: %v", err)
		}
		if a := mustValidate(t, s, f.encode(t)); a.NameID != testNameID {
			t.Errorf("NameID = %q", a.NameID)
		}
	})

	t.Run("bad PEM fails closed", func(t *testing.T) {
		s := New(Options{
			IdPCertificates:    []*x509.Certificate{idp.cert},
			SPDecryptionKeyPEM: []byte("-----BEGIN PRIVATE KEY-----\nbm90IGEga2V5\n-----END PRIVATE KEY-----\n"),
			Audience:           testAudience,
		})
		if s.ConfigError() == nil {
			t.Fatal("ConfigError = nil, want a parse failure")
		}
	})

	t.Run("encrypted PEM refused", func(t *testing.T) {
		if _, err := ParsePrivateKeys([]byte(
			"-----BEGIN RSA PRIVATE KEY-----\n" +
				"Proc-Type: 4,ENCRYPTED\n" +
				"DEK-Info: AES-128-CBC,0123456789ABCDEF0123456789ABCDEF\n\n" +
				"bm90IGEga2V5\n-----END RSA PRIVATE KEY-----\n")); err == nil {
			t.Fatal("ParsePrivateKeys accepted an encrypted PEM block")
		}
	})
}

// keyPEM renders a private key as a PKCS#8 PEM block.
func keyPEM(t *testing.T, key *rsa.PrivateKey) []byte {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("MarshalPKCS8PrivateKey: %v", err)
	}
	var b strings.Builder
	b.WriteString("-----BEGIN PRIVATE KEY-----\n")
	enc := base64.StdEncoding.EncodeToString(der)
	for len(enc) > 64 {
		b.WriteString(enc[:64] + "\n")
		enc = enc[64:]
	}
	b.WriteString(enc + "\n-----END PRIVATE KEY-----\n")
	return []byte(b.String())
}

// TestEncryptedAssertionAlgorithmPolicy pins the algorithms that are refused
// unless the caller explicitly opts in.
func TestEncryptedAssertionAlgorithmPolicy(t *testing.T) {
	idp := newTestIdP(t, "rsa")
	sp := newTestSPKey(t)

	cases := []struct {
		name string
		enc  encryptor
		want string
	}{
		{"RSA-1.5 key transport", encryptor{keyAlg: AlgRSA15}, "rsa-1_5"},
		{"AES-128-CBC content", encryptor{contentAlg: AlgAES128CBC}, "aes128-cbc"},
		{"AES-256-CBC content", encryptor{contentAlg: AlgAES256CBC}, "aes256-cbc"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			enc := tc.enc
			enc.pub = &sp.PublicKey
			f := newFixture(idp)
			f.encrypt = enc.encrypt
			err := mustReject(t, f.strategy(spOption(sp)), f.encode(t))
			if !errors.Is(err, ErrEncrypted) {
				t.Fatalf("err = %v, want it to wrap ErrEncrypted", err)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("err = %v, want it to name %s", err, tc.want)
			}
		})
	}

	t.Run("unknown content algorithm", func(t *testing.T) {
		f := newFixture(idp)
		f.encrypt = (&encryptor{pub: &sp.PublicKey}).encrypt
		f.postSign = func(doc string) string {
			return strings.Replace(doc, AlgAES256GCM, nsXMLEnc+"tripledes-cbc", 1)
		}
		if err := mustReject(t, f.strategy(spOption(sp)), f.encode(t)); !errors.Is(err, ErrEncrypted) {
			t.Errorf("err = %v, want ErrEncrypted", err)
		}
	})

	t.Run("CipherReference refused", func(t *testing.T) {
		f := newFixture(idp)
		f.encrypt = (&encryptor{pub: &sp.PublicKey}).encrypt
		f.postSign = func(doc string) string {
			return strings.Replace(doc, `<xenc:CipherData><xenc:CipherValue>`,
				`<xenc:CipherData><xenc:CipherReference URI="http://attacker.example/x"/><xenc:CipherValue>`, 1)
		}
		if err := mustReject(t, f.strategy(spOption(sp)), f.encode(t)); !errors.Is(err, ErrEncrypted) {
			t.Errorf("err = %v, want ErrEncrypted", err)
		}
	})
}

// TestEncryptedAssertionPlaintextIsHardened: the decrypted bytes go through the
// same strict parser as the outer document, with the same caps.
func TestEncryptedAssertionPlaintextIsHardened(t *testing.T) {
	idp := newTestIdP(t, "rsa")
	sp := newTestSPKey(t)

	t.Run("DOCTYPE inside the plaintext", func(t *testing.T) {
		enc := encryptor{pub: &sp.PublicKey}
		f := newFixture(idp)
		f.signTarget = "response"
		f.encrypt = func(t *testing.T, assertionXML string) string {
			return enc.encrypt(t, `<!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd">]>`+assertionXML)
		}
		if err := mustReject(t, f.strategy(spOption(sp)), f.encode(t)); !errors.Is(err, ErrDoctype) {
			t.Errorf("err = %v, want ErrDoctype", err)
		}
	})

	t.Run("oversized plaintext", func(t *testing.T) {
		enc := encryptor{pub: &sp.PublicKey}
		f := newFixture(idp)
		f.signTarget = "response"
		f.encrypt = enc.encrypt
		s := f.strategy(spOption(sp), func(o *Options) { o.MaxDecryptedBytes = 64 })
		if err := mustReject(t, s, f.encode(t)); !errors.Is(err, ErrDecryptedTooLarge) {
			t.Errorf("err = %v, want ErrDecryptedTooLarge", err)
		}
	})

	t.Run("plaintext that is not an assertion", func(t *testing.T) {
		enc := encryptor{pub: &sp.PublicKey}
		f := newFixture(idp)
		f.signTarget = "response"
		f.encrypt = func(t *testing.T, assertionXML string) string {
			return enc.encrypt(t, `<saml:Nonsense xmlns:saml="`+nsSAMLAssertion+`"/>`)
		}
		mustReject(t, f.strategy(spOption(sp)), f.encode(t))
	})

	t.Run("nested assertion inside the plaintext", func(t *testing.T) {
		enc := encryptor{pub: &sp.PublicKey}
		f := newFixture(idp)
		f.signTarget = "response"
		f.encrypt = func(t *testing.T, assertionXML string) string {
			inner := `<saml:Assertion xmlns:saml="` + nsSAMLAssertion + `" ID="_smuggled"/>`
			return enc.encrypt(t, strings.Replace(assertionXML, `<saml:Issuer>`, inner+`<saml:Issuer>`, 1))
		}
		mustReject(t, f.strategy(spOption(sp)), f.encode(t))
	})

	t.Run("deep nesting inside the plaintext", func(t *testing.T) {
		enc := encryptor{pub: &sp.PublicKey}
		f := newFixture(idp)
		f.signTarget = "response"
		f.encrypt = func(t *testing.T, assertionXML string) string {
			deep := strings.Repeat(`<saml:D>`, 40) + strings.Repeat(`</saml:D>`, 40)
			return enc.encrypt(t, strings.Replace(assertionXML, `<saml:Issuer>`, deep+`<saml:Issuer>`, 1))
		}
		s := f.strategy(spOption(sp), func(o *Options) { o.MaxDepth = 10 })
		mustReject(t, s, f.encode(t))
	})
}

// TestEncryptedAssertionStructure keeps the anti-wrapping placement rule in
// force for the encrypted form.
func TestEncryptedAssertionStructure(t *testing.T) {
	idp := newTestIdP(t, "rsa")
	sp := newTestSPKey(t)

	t.Run("EncryptedAssertion not a child of the response", func(t *testing.T) {
		enc := encryptor{pub: &sp.PublicKey}
		f := newFixture(idp)
		f.postSign = func(doc string) string {
			return strings.Replace(doc, `<samlp:Status>`,
				`<samlp:Extensions>`+enc.encrypt(t, `<saml:Assertion xmlns:saml="`+nsSAMLAssertion+`" ID="_x"/>`)+
					`</samlp:Extensions><samlp:Status>`, 1)
		}
		mustReject(t, f.strategy(spOption(sp)), f.encode(t))
	})

	t.Run("EncryptedAssertion alongside a plaintext assertion", func(t *testing.T) {
		enc := encryptor{pub: &sp.PublicKey}
		f := newFixture(idp)
		f.postSign = func(doc string) string {
			return strings.Replace(doc, `<samlp:Status>`,
				enc.encrypt(t, `<saml:Assertion xmlns:saml="`+nsSAMLAssertion+`" ID="_x"/>`)+`<samlp:Status>`, 1)
		}
		err := mustReject(t, f.strategy(spOption(sp)), f.encode(t))
		if !strings.Contains(err.Error(), "2 assertions") {
			t.Errorf("err = %v, want the two-assertion rejection", err)
		}
	})
}

// TestEncryptedID decrypts a subject identifier that arrived inside a signed
// assertion, which is what makes trusting it sound: the ciphertext is covered
// by the assertion signature.
func TestEncryptedID(t *testing.T) {
	idp := newTestIdP(t, "rsa")
	sp := newTestSPKey(t)
	enc := encryptor{pub: &sp.PublicKey, wrapper: "EncryptedID"}

	t.Run("valid", func(t *testing.T) {
		f := newFixture(idp)
		f.subjectID = enc.encrypt(t,
			`<saml:NameID xmlns:saml="`+nsSAMLAssertion+
				`" Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">`+testNameID+`</saml:NameID>`)

		a := mustValidate(t, f.strategy(spOption(sp)), f.encode(t))
		if a.NameID != testNameID {
			t.Errorf("NameID = %q, want %q", a.NameID, testNameID)
		}
		if !a.EncryptedNameID {
			t.Error("Assertion.EncryptedNameID = false, want true")
		}
		if a.Encrypted {
			t.Error("Assertion.Encrypted = true, want false: only the NameID was encrypted")
		}
	})

	t.Run("no SP key configured", func(t *testing.T) {
		f := newFixture(idp)
		f.subjectID = enc.encrypt(t, `<saml:NameID xmlns:saml="`+nsSAMLAssertion+`">`+testNameID+`</saml:NameID>`)
		if err := mustReject(t, f.strategy(), f.encode(t)); !errors.Is(err, ErrNoDecryptionKey) {
			t.Errorf("err = %v, want ErrNoDecryptionKey", err)
		}
	})

	t.Run("plaintext is not a NameID", func(t *testing.T) {
		f := newFixture(idp)
		f.subjectID = enc.encrypt(t, `<saml:Attribute xmlns:saml="`+nsSAMLAssertion+`" Name="x"/>`)
		mustReject(t, f.strategy(spOption(sp)), f.encode(t))
	})

	t.Run("both NameID and EncryptedID", func(t *testing.T) {
		f := newFixture(idp)
		f.subjectID = `<saml:NameID>` + testNameID + `</saml:NameID>` +
			enc.encrypt(t, `<saml:NameID xmlns:saml="`+nsSAMLAssertion+`">other@example.com</saml:NameID>`)
		mustReject(t, f.strategy(spOption(sp)), f.encode(t))
	})

	t.Run("EncryptedID outside a Subject", func(t *testing.T) {
		f := newFixture(idp)
		f.postSign = func(doc string) string {
			return strings.Replace(doc, `<samlp:Status>`,
				enc.encrypt(t, `<saml:NameID xmlns:saml="`+nsSAMLAssertion+`">x</saml:NameID>`)+`<samlp:Status>`, 1)
		}
		mustReject(t, f.strategy(spOption(sp)), f.encode(t))
	})
}

// assertionElement renders a fixture and returns just its saml:Assertion
// element, namespace-declared so it can be pasted into another response.
func assertionElement(t *testing.T, f *fixture) string {
	t.Helper()
	var out string
	f.replaceAssertion(t, f.xml(t), func(_ *testing.T, fragment string) string {
		out = fragment
		return fragment
	})
	if out == "" {
		t.Fatal("no assertion extracted")
	}
	return out
}

// secondAssertion builds an independently signed assertion with its own ID and
// NameID, for the multi-assertion tests.
func secondAssertion(t *testing.T, idp *testIdP, nameID, signTarget string) string {
	t.Helper()
	f := newFixture(idp)
	f.responseID = "_response2"
	f.assertionID = "_assertion2"
	f.nameID = nameID
	f.signTarget = signTarget
	return assertionElement(t, f)
}

// TestMultipleAssertions covers the opt-in multi-assertion path.
func TestMultipleAssertions(t *testing.T) {
	idp := newTestIdP(t, "rsa")

	t.Run("refused by default", func(t *testing.T) {
		f := newFixture(idp)
		f.extraAssertions = secondAssertion(t, idp, testNameID, "assertion")
		err := mustReject(t, f.strategy(), f.encode(t))
		if !strings.Contains(err.Error(), "2 assertions") {
			t.Errorf("err = %v, want the two-assertion rejection", err)
		}
	})

	t.Run("all signed, same subject", func(t *testing.T) {
		f := newFixture(idp)
		f.extraAssertions = secondAssertion(t, idp, testNameID, "assertion")
		a := mustValidate(t, f.strategy(allowMultiple), f.encode(t))
		if a.NameID != testNameID {
			t.Errorf("NameID = %q, want %q", a.NameID, testNameID)
		}
		if len(a.Assertions) != 2 {
			t.Fatalf("len(Assertions) = %d, want 2", len(a.Assertions))
		}
		if a.Assertions[0].ID != "_assertion1" || a.Assertions[1].ID != "_assertion2" {
			t.Errorf("Assertions = %q, %q; want document order",
				a.Assertions[0].ID, a.Assertions[1].ID)
		}
	})

	t.Run("one unsigned among many", func(t *testing.T) {
		f := newFixture(idp)
		f.extraAssertions = secondAssertion(t, idp, testNameID, "")
		if err := mustReject(t, f.strategy(allowMultiple), f.encode(t)); !errors.Is(err, ErrNoSignature) {
			t.Errorf("err = %v, want ErrNoSignature", err)
		}
	})

	t.Run("one invalid among many", func(t *testing.T) {
		f := newFixture(idp)
		expired := newFixture(idp)
		expired.responseID = "_response2"
		expired.assertionID = "_assertion2"
		expired.notBefore = testNow.Add(-2 * time.Hour)
		expired.notOnOrAfter = testNow.Add(-1 * time.Hour)
		f.extraAssertions = assertionElement(t, expired)
		if err := mustReject(t, f.strategy(allowMultiple), f.encode(t)); !errors.Is(err, ErrConditions) {
			t.Errorf("err = %v, want ErrConditions", err)
		}
	})

	t.Run("ambiguous NameIDs", func(t *testing.T) {
		f := newFixture(idp)
		f.extraAssertions = secondAssertion(t, idp, "bob@example.com", "assertion")
		if err := mustReject(t, f.strategy(allowMultiple), f.encode(t)); !errors.Is(err, ErrAmbiguousAssertion) {
			t.Errorf("err = %v, want ErrAmbiguousAssertion", err)
		}
	})

	t.Run("ambiguity resolved by a selector", func(t *testing.T) {
		f := newFixture(idp)
		f.extraAssertions = secondAssertion(t, idp, "bob@example.com", "assertion")
		s := f.strategy(allowMultiple, func(o *Options) {
			o.SelectAssertion = func(as []*Assertion) (*Assertion, error) {
				for _, a := range as {
					if a.NameID == "bob@example.com" {
						return a, nil
					}
				}
				return nil, nil
			}
		})
		if a := mustValidate(t, s, f.encode(t)); a.NameID != "bob@example.com" {
			t.Errorf("NameID = %q, want bob@example.com", a.NameID)
		}
	})

	t.Run("selector returning a foreign assertion", func(t *testing.T) {
		f := newFixture(idp)
		f.extraAssertions = secondAssertion(t, idp, "bob@example.com", "assertion")
		s := f.strategy(allowMultiple, func(o *Options) {
			o.SelectAssertion = func([]*Assertion) (*Assertion, error) {
				return &Assertion{NameID: "root@example.com"}, nil
			}
		})
		mustReject(t, s, f.encode(t))
	})

	t.Run("selector returning nil", func(t *testing.T) {
		f := newFixture(idp)
		f.extraAssertions = secondAssertion(t, idp, "bob@example.com", "assertion")
		s := f.strategy(allowMultiple, func(o *Options) {
			o.SelectAssertion = func([]*Assertion) (*Assertion, error) { return nil, nil }
		})
		mustReject(t, s, f.encode(t))
	})

	t.Run("a replayed assertion rejects the whole response", func(t *testing.T) {
		f := newFixture(idp)
		f.extraAssertions = secondAssertion(t, idp, testNameID, "assertion")
		s := f.strategy(allowMultiple)
		b64 := f.encode(t)
		mustValidate(t, s, b64)
		if err := mustReject(t, s, b64); !errors.Is(err, ErrReplay) {
			t.Errorf("err = %v, want ErrReplay", err)
		}
	})

	t.Run("still rejects a nested assertion", func(t *testing.T) {
		f := newFixture(idp)
		f.postSign = func(doc string) string {
			return strings.Replace(doc, `<saml:AttributeStatement>`,
				`<saml:Assertion ID="_nested"/><saml:AttributeStatement>`, 1)
		}
		mustReject(t, f.strategy(allowMultiple), f.encode(t))
	})

	t.Run("mixed plaintext and encrypted", func(t *testing.T) {
		sp := newTestSPKey(t)
		enc := encryptor{pub: &sp.PublicKey}
		f := newFixture(idp)
		f.extraAssertions = enc.encrypt(t, secondAssertion(t, idp, testNameID, "assertion"))
		a := mustValidate(t, f.strategy(allowMultiple, spOption(sp)), f.encode(t))
		if len(a.Assertions) != 2 {
			t.Fatalf("len(Assertions) = %d, want 2", len(a.Assertions))
		}
		if a.Assertions[0].Encrypted || !a.Assertions[1].Encrypted {
			t.Errorf("Encrypted flags = %v/%v, want false/true",
				a.Assertions[0].Encrypted, a.Assertions[1].Encrypted)
		}
	})
}

// allowMultiple is the option override the multi-assertion tests share.
func allowMultiple(o *Options) { o.AllowMultipleAssertions = true }
