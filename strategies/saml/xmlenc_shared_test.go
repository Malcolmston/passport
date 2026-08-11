package saml

import (
	"crypto/aes"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
)

// This file covers XML Encryption under a pre-shared symmetric key: an
// xenc:EncryptedData with no xenc:EncryptedKey, and an xenc:EncryptedKey
// wrapped with RFC 3394 AES-KeyWrap.
//
// As in xmlenc_test.go the encryptor here shares no code with the decryptor. In
// particular testAESKeyWrap below is written from RFC 3394 section 2.2.1 (the
// wrap direction) rather than being the inverse of xmlenc.go's unwrap, and it
// is checked against the published vectors in RFC 3394 section 4.

// sharedEncryptor renders a saml:EncryptedAssertion or saml:EncryptedID whose
// content key is a pre-shared symmetric key, either used directly or reached
// through an AES-KeyWrap'd EncryptedKey.
type sharedEncryptor struct {
	// key is the pre-shared key: the content key when kw is "", the
	// key-encryption key otherwise.
	key []byte

	// keyName is written as ds:KeyInfo/ds:KeyName; "" omits the KeyInfo
	// entirely, which is the "try every configured key" case.
	keyName string

	// contentAlg defaults to AES-256-GCM.
	contentAlg string

	// kw, when set to one of the kw-aes* URIs, wraps a freshly generated
	// session key under key and emits an xenc:EncryptedKey for it.
	kw string

	// wrapper is the container's local name; defaults to
	// "EncryptedAssertion".
	wrapper string

	// mutateCiphertext corrupts the content ciphertext after encryption.
	mutateCiphertext func([]byte) []byte
}

func (e *sharedEncryptor) encrypt(t *testing.T, plaintext string) string {
	t.Helper()
	wrapper := e.wrapper
	if wrapper == "" {
		wrapper = "EncryptedAssertion"
	}
	contentAlg := e.contentAlg
	if contentAlg == "" {
		contentAlg = AlgAES256GCM
	}
	alg, ok := contentAlgorithms[contentAlg]
	if !ok {
		t.Fatalf("unknown content algorithm %q", contentAlg)
	}

	// keyInfo names the pre-shared key, wherever it ends up being attached.
	keyInfo := ""
	if e.keyName != "" {
		keyInfo = `<ds:KeyInfo xmlns:ds="` + nsDSig + `"><ds:KeyName>` + e.keyName + `</ds:KeyName></ds:KeyInfo>`
	}

	contentKey := e.key
	encryptedKey := ""
	if e.kw != "" {
		contentKey = make([]byte, alg.keyLen)
		if _, err := rand.Read(contentKey); err != nil {
			t.Fatalf("rand: %v", err)
		}
		wrapped := testAESKeyWrap(t, e.key, contentKey)
		encryptedKey = `<xenc:EncryptedKey xmlns:xenc="` + nsXMLEnc + `">` +
			`<xenc:EncryptionMethod Algorithm="` + e.kw + `"/>` + keyInfo +
			`<xenc:CipherData><xenc:CipherValue>` +
			base64.StdEncoding.EncodeToString(wrapped) +
			`</xenc:CipherValue></xenc:CipherData></xenc:EncryptedKey>`
		// The EncryptedData's KeyInfo now carries the EncryptedKey; the
		// ds:KeyName went inside it, naming the KEK.
		keyInfo = `<ds:KeyInfo xmlns:ds="` + nsDSig + `">` + encryptedKey + `</ds:KeyInfo>`
	}

	// sealContent belongs to the fixture encryptor in xmlenc_test.go and is
	// pure test-side code; reusing it keeps one wire-format writer.
	base := &encryptor{}
	ciphertext := base.sealContent(t, alg, contentKey, []byte(plaintext))
	if e.mutateCiphertext != nil {
		ciphertext = e.mutateCiphertext(ciphertext)
	}

	return `<saml:` + wrapper + ` xmlns:saml="` + nsSAMLAssertion + `">` +
		`<xenc:EncryptedData xmlns:xenc="` + nsXMLEnc + `" Type="` + nsXMLEnc + `Element">` +
		`<xenc:EncryptionMethod Algorithm="` + contentAlg + `"/>` +
		keyInfo +
		`<xenc:CipherData><xenc:CipherValue>` +
		base64.StdEncoding.EncodeToString(ciphertext) +
		`</xenc:CipherValue></xenc:CipherData>` +
		`</xenc:EncryptedData>` +
		`</saml:` + wrapper + `>`
}

// testAESKeyWrap is the RFC 3394 section 2.2.1 wrap algorithm, written in the
// forward direction so it is an independent check on xmlenc.go's unwrap.
func testAESKeyWrap(t *testing.T, kek, key []byte) []byte {
	t.Helper()
	if len(key)%8 != 0 || len(key) < 16 {
		t.Fatalf("key data is %d bytes; RFC 3394 needs at least two 8-byte blocks", len(key))
	}
	block, err := aes.NewCipher(kek)
	if err != nil {
		t.Fatalf("aes.NewCipher: %v", err)
	}
	n := len(key) / 8
	a := []byte{0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6}
	r := append([]byte(nil), key...)

	buf := make([]byte, 16)
	for j := 0; j < 6; j++ {
		for i := 1; i <= n; i++ {
			copy(buf[:8], a)
			copy(buf[8:], r[(i-1)*8:i*8])
			block.Encrypt(buf, buf)
			// A = MSB(64, B) ^ t, with t = n*j + i.
			t64 := uint64(n*j + i)
			copy(a, buf[:8])
			for k := 0; k < 8; k++ {
				a[7-k] ^= byte(t64 >> (8 * k))
			}
			copy(r[(i-1)*8:i*8], buf[8:])
		}
	}
	return append(a, r...)
}

// sharedOption configures a strategy with pre-shared keys.
func sharedOption(keys map[string][]byte) func(*Options) {
	return func(o *Options) { o.SPSharedKeys = keys }
}

// testSharedKey returns a deterministic key of n bytes. The bytes are
// arbitrary; only the length matters to the code under test.
func testSharedKey(n int, fill byte) []byte {
	k := make([]byte, n)
	for i := range k {
		k[i] = fill + byte(i)
	}
	return k
}

// TestAESKeyUnwrapRFC3394 checks the unwrap against the published vectors of
// RFC 3394 section 4, and checks that the test-side wrap reproduces them, so
// neither implementation is trusted on the other's word.
func TestAESKeyUnwrapRFC3394(t *testing.T) {
	cases := []struct {
		name    string
		kek     string
		key     string
		wrapped string
	}{
		{ // RFC 3394 section 4.1
			"128-bit key with 128-bit KEK",
			"000102030405060708090A0B0C0D0E0F",
			"00112233445566778899AABBCCDDEEFF",
			"1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5",
		},
		{ // RFC 3394 section 4.2
			"128-bit key with 192-bit KEK",
			"000102030405060708090A0B0C0D0E0F1011121314151617",
			"00112233445566778899AABBCCDDEEFF",
			"96778B25AE6CA435F92B5B97C050AED2468AB8A17AD84E5D",
		},
		{ // RFC 3394 section 4.3
			"128-bit key with 256-bit KEK",
			"000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
			"00112233445566778899AABBCCDDEEFF",
			"64E8C3F9CE0F5BA263E9777905818A2A93C8191E7D6E8AE7",
		},
		{ // RFC 3394 section 4.4
			"192-bit key with 192-bit KEK",
			"000102030405060708090A0B0C0D0E0F1011121314151617",
			"00112233445566778899AABBCCDDEEFF0001020304050607",
			"031D33264E15D33268F24EC260743EDCE1C6C7DDEE725A936BA814915C6762D2",
		},
		{ // RFC 3394 section 4.5
			"192-bit key with 256-bit KEK",
			"000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
			"00112233445566778899AABBCCDDEEFF0001020304050607",
			"A8F9BC1612C68B3FF6E6F4FBE30E71E4769C8B80A32CB8958CD5D17D6B254DA1",
		},
		{ // RFC 3394 section 4.6
			"256-bit key with 256-bit KEK",
			"000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
			"00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F",
			"28C9F404C4B810F4CBCCB35CFB87F8263F5786E2D80ED326CBC7F0E71A99F43BFB988B9B7A02DD21",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			kek := mustHex(t, tc.kek)
			key := mustHex(t, tc.key)
			wrapped := mustHex(t, tc.wrapped)

			got, err := aesKeyUnwrap(kek, wrapped)
			if err != nil {
				t.Fatalf("aesKeyUnwrap: %v", err)
			}
			if !strings.EqualFold(hex.EncodeToString(got), tc.key) {
				t.Errorf("unwrapped %X, want %s", got, tc.key)
			}
			if gotWrap := testAESKeyWrap(t, kek, key); !strings.EqualFold(hex.EncodeToString(gotWrap), tc.wrapped) {
				t.Errorf("testAESKeyWrap = %X, want %s", gotWrap, tc.wrapped)
			}
		})
	}

	t.Run("integrity check rejects a wrong KEK", func(t *testing.T) {
		kek := mustHex(t, "000102030405060708090A0B0C0D0E0F")
		wrapped := mustHex(t, "1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5")
		kek[0] ^= 0xFF
		if _, err := aesKeyUnwrap(kek, wrapped); !errors.Is(err, ErrDecryptFailed) {
			t.Errorf("err = %v, want ErrDecryptFailed", err)
		}
	})

	t.Run("malformed lengths are refused", func(t *testing.T) {
		kek := mustHex(t, "000102030405060708090A0B0C0D0E0F")
		for _, n := range []int{0, 8, 16, 23, 25, 31} {
			if _, err := aesKeyUnwrap(kek, make([]byte, n)); !errors.Is(err, ErrDecryptFailed) {
				t.Errorf("len %d: err = %v, want ErrDecryptFailed", n, err)
			}
		}
	})
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hex %q: %v", s, err)
	}
	return b
}

// TestSharedKeyEncryptedAssertion covers the accepting cases: both signature
// coverage paths, every AES size, named and unnamed keys, and AES-KeyWrap.
func TestSharedKeyEncryptedAssertion(t *testing.T) {
	idp := newTestIdP(t, "rsa")

	cases := []struct {
		name       string
		enc        sharedEncryptor
		keys       map[string][]byte
		signTarget string
		options    []func(*Options)
	}{
		{
			"AES-256-GCM, unnamed key, inner signature",
			sharedEncryptor{key: testSharedKey(32, 1)},
			map[string][]byte{"": testSharedKey(32, 1)},
			"assertion", nil,
		},
		{
			"AES-256-GCM, unnamed key, response signature",
			sharedEncryptor{key: testSharedKey(32, 1)},
			map[string][]byte{"": testSharedKey(32, 1)},
			"response", nil,
		},
		{
			"AES-128-GCM",
			sharedEncryptor{key: testSharedKey(16, 2), contentAlg: AlgAES128GCM},
			map[string][]byte{"": testSharedKey(16, 2)},
			"assertion", nil,
		},
		{
			"AES-192-GCM",
			sharedEncryptor{key: testSharedKey(24, 3), contentAlg: AlgAES192GCM},
			map[string][]byte{"": testSharedKey(24, 3)},
			"assertion", nil,
		},
		{
			"named key",
			sharedEncryptor{key: testSharedKey(32, 4), keyName: "sso-2026"},
			map[string][]byte{"sso-2026": testSharedKey(32, 4)},
			"assertion", nil,
		},
		{
			"AES-256-CBC when explicitly enabled",
			sharedEncryptor{key: testSharedKey(32, 5), contentAlg: AlgAES256CBC},
			map[string][]byte{"": testSharedKey(32, 5)},
			"assertion",
			[]func(*Options){func(o *Options) { o.AllowCBCDecryption = true }},
		},
		{
			"AES-256 KeyWrap of the session key",
			sharedEncryptor{key: testSharedKey(32, 6), kw: AlgAESKW256},
			map[string][]byte{"": testSharedKey(32, 6)},
			"assertion", nil,
		},
		{
			"AES-128 KeyWrap, named KEK",
			sharedEncryptor{key: testSharedKey(16, 7), kw: AlgAESKW128, keyName: "kek-a"},
			map[string][]byte{"kek-a": testSharedKey(16, 7)},
			"assertion", nil,
		},
		{
			"AES-192 KeyWrap of an AES-128 session key",
			sharedEncryptor{key: testSharedKey(24, 8), kw: AlgAESKW192, contentAlg: AlgAES128GCM},
			map[string][]byte{"": testSharedKey(24, 8)},
			"response", nil,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			enc := tc.enc
			f := newFixture(idp)
			f.signTarget = tc.signTarget
			f.encrypt = enc.encrypt

			opts := append([]func(*Options){sharedOption(tc.keys)}, tc.options...)
			s := f.strategy(opts...)
			if err := s.ConfigError(); err != nil {
				t.Fatalf("ConfigError: %v", err)
			}
			a := mustValidate(t, s, f.encode(t))
			if a.NameID != testNameID {
				t.Errorf("NameID = %q, want %q", a.NameID, testNameID)
			}
			if !a.Encrypted {
				t.Error("Assertion.Encrypted = false, want true")
			}
		})
	}
}

// TestSharedKeyEncryptedAssertionWithoutSignature is the headline case. A
// pre-shared key is a shared secret, so anyone holding it can encrypt whatever
// they like: an assertion that decrypts perfectly must still be rejected when
// no identity provider signature covers it.
func TestSharedKeyEncryptedAssertionWithoutSignature(t *testing.T) {
	idp := newTestIdP(t, "rsa")
	key := testSharedKey(32, 9)
	keys := map[string][]byte{"": key}

	t.Run("no signature anywhere", func(t *testing.T) {
		enc := sharedEncryptor{key: key}
		f := newFixture(idp)
		f.signTarget = ""
		f.encrypt = enc.encrypt
		if err := mustReject(t, f.strategy(sharedOption(keys)), f.encode(t)); !errors.Is(err, ErrNoSignature) {
			t.Errorf("err = %v, want ErrNoSignature", err)
		}
	})

	t.Run("forged plaintext under the shared key", func(t *testing.T) {
		// The realistic attack: someone who holds the shared key strips the
		// IdP's signature, renames the subject, and re-encrypts.
		enc := sharedEncryptor{key: key}
		f := newFixture(idp)
		f.signTarget = "assertion"
		f.encrypt = func(t *testing.T, assertionXML string) string {
			start := strings.Index(assertionXML, `<ds:Signature`)
			end := strings.Index(assertionXML, `</ds:Signature>`) + len(`</ds:Signature>`)
			forged := assertionXML[:start] + assertionXML[end:]
			forged = strings.ReplaceAll(forged, testNameID, "attacker@evil.example")
			return enc.encrypt(t, forged)
		}
		if err := mustReject(t, f.strategy(sharedOption(keys)), f.encode(t)); !errors.Is(err, ErrNoSignature) {
			t.Errorf("err = %v, want ErrNoSignature", err)
		}
	})

	t.Run("forged plaintext under a KeyWrap'd session key", func(t *testing.T) {
		enc := sharedEncryptor{key: key, kw: AlgAESKW256}
		f := newFixture(idp)
		f.signTarget = "assertion"
		f.encrypt = func(t *testing.T, assertionXML string) string {
			start := strings.Index(assertionXML, `<ds:Signature`)
			end := strings.Index(assertionXML, `</ds:Signature>`) + len(`</ds:Signature>`)
			return enc.encrypt(t, assertionXML[:start]+assertionXML[end:])
		}
		if err := mustReject(t, f.strategy(sharedOption(keys)), f.encode(t)); !errors.Is(err, ErrNoSignature) {
			t.Errorf("err = %v, want ErrNoSignature", err)
		}
	})

	t.Run("tampered ciphertext under a response signature", func(t *testing.T) {
		// The other direction: the outer signature covers the ciphertext, so
		// even the holder of the shared key cannot substitute one.
		enc := sharedEncryptor{key: key}
		f := newFixture(idp)
		f.signTarget = "response"
		f.encrypt = enc.encrypt
		f.postSign = func(doc string) string {
			i := strings.Index(doc, `<xenc:CipherValue>`)
			if i < 0 {
				t.Fatal("no CipherValue in fixture")
			}
			j := i + len(`<xenc:CipherValue>`)
			return doc[:j] + swapTwo(doc[j:j+8]) + doc[j+8:]
		}
		if err := mustReject(t, f.strategy(sharedOption(keys)), f.encode(t)); !errors.Is(err, ErrSignatureInvalid) {
			t.Errorf("err = %v, want ErrSignatureInvalid", err)
		}
	})
}

// TestSharedKeySelection covers ds:KeyName driven selection and its failures.
func TestSharedKeySelection(t *testing.T) {
	idp := newTestIdP(t, "rsa")
	oldKey := testSharedKey(32, 10)
	newKey := testSharedKey(32, 20)
	rollover := map[string][]byte{"old": oldKey, "new": newKey}

	for _, name := range []string{"old", "new"} {
		t.Run("KeyName "+name+" selects its key", func(t *testing.T) {
			enc := sharedEncryptor{key: rollover[name], keyName: name}
			f := newFixture(idp)
			f.encrypt = enc.encrypt
			if a := mustValidate(t, f.strategy(sharedOption(rollover)), f.encode(t)); a.NameID != testNameID {
				t.Errorf("NameID = %q", a.NameID)
			}
		})
	}

	t.Run("unnamed key is found among several", func(t *testing.T) {
		enc := sharedEncryptor{key: newKey}
		f := newFixture(idp)
		f.encrypt = enc.encrypt
		if a := mustValidate(t, f.strategy(sharedOption(rollover)), f.encode(t)); a.NameID != testNameID {
			t.Errorf("NameID = %q", a.NameID)
		}
	})

	t.Run("KeyName naming a key that is not the one used", func(t *testing.T) {
		// Naming "old" but encrypting under "new" must fail: the name pins
		// the choice, it is not a hint to fall back from.
		enc := sharedEncryptor{key: newKey, keyName: "old"}
		f := newFixture(idp)
		f.encrypt = enc.encrypt
		if err := mustReject(t, f.strategy(sharedOption(rollover)), f.encode(t)); !errors.Is(err, ErrDecryptFailed) {
			t.Errorf("err = %v, want ErrDecryptFailed", err)
		}
	})

	t.Run("unknown KeyName", func(t *testing.T) {
		enc := sharedEncryptor{key: newKey, keyName: "retired"}
		f := newFixture(idp)
		f.encrypt = enc.encrypt
		err := mustReject(t, f.strategy(sharedOption(rollover)), f.encode(t))
		if !errors.Is(err, ErrEncrypted) {
			t.Fatalf("err = %v, want it to wrap ErrEncrypted", err)
		}
		if !strings.Contains(err.Error(), `"retired"`) {
			t.Errorf("err = %v, want it to name the unknown key", err)
		}
	})

	t.Run("KeyName of the wrong length for the algorithm", func(t *testing.T) {
		enc := sharedEncryptor{key: testSharedKey(32, 30), keyName: "short"}
		f := newFixture(idp)
		f.encrypt = enc.encrypt
		s := f.strategy(sharedOption(map[string][]byte{"short": testSharedKey(16, 30)}))
		if err := s.ConfigError(); err != nil {
			t.Fatalf("ConfigError: %v", err)
		}
		err := mustReject(t, s, f.encode(t))
		if !errors.Is(err, ErrEncrypted) || !strings.Contains(err.Error(), "16 bytes") {
			t.Errorf("err = %v, want a length mismatch naming 16 bytes", err)
		}
	})

	t.Run("unwrapping KEK is selected by KeyName too", func(t *testing.T) {
		enc := sharedEncryptor{key: testSharedKey(16, 40), kw: AlgAESKW128, keyName: "kek"}
		f := newFixture(idp)
		f.encrypt = enc.encrypt
		keys := map[string][]byte{"kek": testSharedKey(16, 40), "other": testSharedKey(16, 41)}
		if a := mustValidate(t, f.strategy(sharedOption(keys)), f.encode(t)); a.NameID != testNameID {
			t.Errorf("NameID = %q", a.NameID)
		}
	})
}

// TestSharedKeyFailures covers the rejections: a wrong key, no key, and the
// refusal to fall through to anything weaker.
func TestSharedKeyFailures(t *testing.T) {
	idp := newTestIdP(t, "rsa")
	key := testSharedKey(32, 50)

	t.Run("wrong shared key", func(t *testing.T) {
		enc := sharedEncryptor{key: key}
		f := newFixture(idp)
		f.encrypt = enc.encrypt
		s := f.strategy(sharedOption(map[string][]byte{"": testSharedKey(32, 51)}))
		if err := mustReject(t, s, f.encode(t)); !errors.Is(err, ErrDecryptFailed) {
			t.Errorf("err = %v, want ErrDecryptFailed", err)
		}
	})

	t.Run("wrong KEK", func(t *testing.T) {
		enc := sharedEncryptor{key: key, kw: AlgAESKW256}
		f := newFixture(idp)
		f.encrypt = enc.encrypt
		s := f.strategy(sharedOption(map[string][]byte{"": testSharedKey(32, 52)}))
		if err := mustReject(t, s, f.encode(t)); !errors.Is(err, ErrDecryptFailed) {
			t.Errorf("err = %v, want ErrDecryptFailed", err)
		}
	})

	t.Run("no key configured at all", func(t *testing.T) {
		enc := sharedEncryptor{key: key}
		f := newFixture(idp)
		f.encrypt = enc.encrypt
		if err := mustReject(t, f.strategy(), f.encode(t)); !errors.Is(err, ErrNoDecryptionKey) {
			t.Errorf("err = %v, want ErrNoDecryptionKey", err)
		}
	})

	t.Run("only an RSA decryption key configured", func(t *testing.T) {
		// An EncryptedData with no EncryptedKey is not something an RSA key
		// can ever open; it must be rejected outright, never fall through.
		enc := sharedEncryptor{key: key}
		f := newFixture(idp)
		f.encrypt = enc.encrypt
		err := mustReject(t, f.strategy(spOption(newTestSPKey(t))), f.encode(t))
		if !errors.Is(err, ErrNoSharedKey) {
			t.Errorf("err = %v, want ErrNoSharedKey", err)
		}
		if !errors.Is(err, ErrEncrypted) {
			t.Errorf("err = %v, want it to wrap ErrEncrypted", err)
		}
	})

	t.Run("no shared key of the content algorithm's length", func(t *testing.T) {
		enc := sharedEncryptor{key: key} // AES-256-GCM content
		f := newFixture(idp)
		f.encrypt = enc.encrypt
		s := f.strategy(sharedOption(map[string][]byte{"": testSharedKey(16, 53)}))
		if err := mustReject(t, s, f.encode(t)); !errors.Is(err, ErrNoSharedKey) {
			t.Errorf("err = %v, want ErrNoSharedKey", err)
		}
	})

	t.Run("no shared key of the KeyWrap algorithm's length", func(t *testing.T) {
		enc := sharedEncryptor{key: testSharedKey(16, 54), kw: AlgAESKW128}
		f := newFixture(idp)
		f.encrypt = enc.encrypt
		s := f.strategy(sharedOption(map[string][]byte{"": testSharedKey(32, 54)}))
		err := mustReject(t, s, f.encode(t))
		if !errors.Is(err, ErrEncrypted) || !strings.Contains(err.Error(), "kw-aes128") {
			t.Errorf("err = %v, want a rejection naming kw-aes128", err)
		}
	})

	t.Run("AES-CBC is still gated", func(t *testing.T) {
		enc := sharedEncryptor{key: key, contentAlg: AlgAES256CBC}
		f := newFixture(idp)
		f.encrypt = enc.encrypt
		err := mustReject(t, f.strategy(sharedOption(map[string][]byte{"": key})), f.encode(t))
		if !errors.Is(err, ErrEncrypted) || !strings.Contains(err.Error(), "aes256-cbc") {
			t.Errorf("err = %v, want the AES-CBC refusal", err)
		}
	})

	t.Run("CBC failures stay indistinguishable", func(t *testing.T) {
		enc := sharedEncryptor{key: key, contentAlg: AlgAES256CBC,
			mutateCiphertext: func(b []byte) []byte {
				out := append([]byte(nil), b...)
				out[len(out)/2] ^= 0x01
				return out
			}}
		f := newFixture(idp)
		f.encrypt = enc.encrypt
		err := mustReject(t, f.strategy(sharedOption(map[string][]byte{"": key}),
			func(o *Options) { o.AllowCBCDecryption = true }), f.encode(t))
		if got := err.Error(); got != ErrDecryptFailed.Error() {
			t.Errorf("err.Error() = %q, want the generic %q", got, ErrDecryptFailed.Error())
		}
	})

	t.Run("CipherReference is still refused", func(t *testing.T) {
		enc := sharedEncryptor{key: key}
		f := newFixture(idp)
		f.encrypt = enc.encrypt
		f.postSign = func(doc string) string {
			return strings.Replace(doc, `<xenc:CipherData><xenc:CipherValue>`,
				`<xenc:CipherData><xenc:CipherReference URI="http://attacker.example/x"/><xenc:CipherValue>`, 1)
		}
		if err := mustReject(t, f.strategy(sharedOption(map[string][]byte{"": key})), f.encode(t)); !errors.Is(err, ErrEncrypted) {
			t.Errorf("err = %v, want ErrEncrypted", err)
		}
	})

	t.Run("MaxDecryptedBytes still applies", func(t *testing.T) {
		enc := sharedEncryptor{key: key}
		f := newFixture(idp)
		f.signTarget = "response"
		f.encrypt = enc.encrypt
		s := f.strategy(sharedOption(map[string][]byte{"": key}),
			func(o *Options) { o.MaxDecryptedBytes = 64 })
		if err := mustReject(t, s, f.encode(t)); !errors.Is(err, ErrDecryptedTooLarge) {
			t.Errorf("err = %v, want ErrDecryptedTooLarge", err)
		}
	})

	t.Run("DOCTYPE inside the plaintext", func(t *testing.T) {
		enc := sharedEncryptor{key: key}
		f := newFixture(idp)
		f.signTarget = "response"
		f.encrypt = func(t *testing.T, assertionXML string) string {
			return enc.encrypt(t, `<!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd">]>`+assertionXML)
		}
		if err := mustReject(t, f.strategy(sharedOption(map[string][]byte{"": key})), f.encode(t)); !errors.Is(err, ErrDoctype) {
			t.Errorf("err = %v, want ErrDoctype", err)
		}
	})
}

// TestSharedKeyConfiguration pins the fail-closed construction checks.
func TestSharedKeyConfiguration(t *testing.T) {
	idp := newTestIdP(t, "rsa")

	t.Run("wrong key length is a ConfigError", func(t *testing.T) {
		for _, n := range []int{0, 1, 15, 17, 20, 31, 33, 64} {
			s := New(Options{
				IdPCertificates: []*x509.Certificate{idp.cert},
				Audience:        testAudience,
				SPSharedKeys:    map[string][]byte{"bad": make([]byte, n)},
			})
			err := s.ConfigError()
			if err == nil {
				t.Fatalf("%d-byte key: ConfigError = nil, want a rejection", n)
			}
			if !strings.Contains(err.Error(), `"bad"`) {
				t.Errorf("%d-byte key: err = %v, want it to name the key", n, err)
			}
		}
	})

	t.Run("valid lengths are accepted", func(t *testing.T) {
		for _, n := range []int{16, 24, 32} {
			s := New(Options{
				IdPCertificates: []*x509.Certificate{idp.cert},
				Audience:        testAudience,
				SPSharedKeys:    map[string][]byte{"ok": make([]byte, n)},
			})
			if err := s.ConfigError(); err != nil {
				t.Errorf("%d-byte key: ConfigError = %v", n, err)
			}
		}
	})

	t.Run("a bad key makes every Validate fail", func(t *testing.T) {
		key := testSharedKey(32, 60)
		enc := sharedEncryptor{key: key}
		f := newFixture(idp)
		f.encrypt = enc.encrypt
		s := f.strategy(sharedOption(map[string][]byte{"": key, "bad": make([]byte, 7)}))
		if s.ConfigError() == nil {
			t.Fatal("ConfigError = nil, want a rejection")
		}
	})

	t.Run("the caller's map is copied", func(t *testing.T) {
		key := testSharedKey(32, 70)
		keys := map[string][]byte{"": append([]byte(nil), key...)}
		enc := sharedEncryptor{key: key}
		f := newFixture(idp)
		f.encrypt = enc.encrypt
		s := f.strategy(sharedOption(keys))
		// Mutating the caller's map and its key bytes after construction must
		// not change what the strategy accepts.
		keys[""][0] ^= 0xFF
		delete(keys, "")
		keys["injected"] = testSharedKey(32, 71)
		if a := mustValidate(t, s, f.encode(t)); a.NameID != testNameID {
			t.Errorf("NameID = %q", a.NameID)
		}
	})
}
