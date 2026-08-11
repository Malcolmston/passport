package saml

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"hash"
	"sort"
	"strings"
)

// This file implements the subset of XML Encryption 1.0/1.1 that SAML uses:
// decrypting a saml:EncryptedAssertion or saml:EncryptedID that an identity
// provider encrypted to this service provider's public key.
//
// # Decryption is not authentication
//
// The single most important property of this file is what it does *not* do.
// Anyone who has the service provider's public key — which is published in SP
// metadata, so: anyone — can produce a well-formed EncryptedAssertion carrying
// any subject they like. Successfully decrypting a blob therefore says nothing
// whatsoever about who produced it. Every decrypted assertion is handed back to
// the same signature-verification and condition-checking pipeline a plaintext
// assertion goes through, and is rejected unless a signature the identity
// provider produced covers it. See validate.go for the two coverage paths.
//
// A pre-shared symmetric key (Options.SPSharedKeys) makes that rule more
// important, not less. Under RSA key transport only the identity provider can
// encrypt and only this service provider can decrypt; a shared secret collapses
// both properties, so anyone holding the key — including any other party it was
// ever shared with — can mint ciphertext this file will happily decrypt. The
// signature-coverage requirement is the only thing standing between that and a
// forged login, and this file routes pre-shared-key content through exactly the
// same check.
//
// # Algorithm policy
//
// Key transport is RSA-OAEP only by default. RSA-PKCS#1 v1.5 key transport
// (#rsa-1_5) is Bleichenbacher-attackable and is refused unless
// Options.AllowRSA15 is set. Content encryption is AES-GCM by default; AES-CBC
// is the classic XML Encryption padding-oracle target (Jager & Somorovsky,
// "How To Break XML Encryption", CCS 2011) and is refused unless
// Options.AllowCBCDecryption is set.

// XML Encryption namespaces.
const (
	nsXMLEnc   = "http://www.w3.org/2001/04/xmlenc#"
	nsXMLEnc11 = "http://www.w3.org/2009/xmlenc11#"
)

// Key transport algorithm URIs.
const (
	// AlgRSAOAEPMGF1P is RSA-OAEP with MGF1-SHA1 (XML Encryption 1.0). The
	// digest used for the OAEP label is taken from the ds:DigestMethod child
	// of the EncryptionMethod and defaults to SHA-1.
	AlgRSAOAEPMGF1P = nsXMLEnc + "rsa-oaep-mgf1p"
	// AlgRSAOAEP is RSA-OAEP with an explicit xenc11:MGF (XML Encryption
	// 1.1).
	AlgRSAOAEP = nsXMLEnc11 + "rsa-oaep"
	// AlgRSA15 is RSA-PKCS#1 v1.5 key transport. It is refused unless
	// Options.AllowRSA15 is set; see that field for why.
	AlgRSA15 = nsXMLEnc + "rsa-1_5"
)

// Symmetric key-wrap algorithm URIs (RFC 3394 AES Key Wrap). The wrapping key
// is one of the pre-shared keys in Options.SPSharedKeys.
const (
	AlgAESKW128 = nsXMLEnc + "kw-aes128"
	AlgAESKW192 = nsXMLEnc + "kw-aes192"
	AlgAESKW256 = nsXMLEnc + "kw-aes256"
)

// keyWrapAlgorithms maps a key-wrap URI to the exact KEK length it requires.
var keyWrapAlgorithms = map[string]int{
	AlgAESKW128: 16,
	AlgAESKW192: 24,
	AlgAESKW256: 32,
}

// Content encryption algorithm URIs.
const (
	AlgAES128GCM = nsXMLEnc11 + "aes128-gcm"
	AlgAES192GCM = nsXMLEnc11 + "aes192-gcm"
	AlgAES256GCM = nsXMLEnc11 + "aes256-gcm"
	AlgAES128CBC = nsXMLEnc + "aes128-cbc"
	AlgAES192CBC = nsXMLEnc + "aes192-cbc"
	AlgAES256CBC = nsXMLEnc + "aes256-cbc"
)

// Errors reported by decryption. Every one of them wraps ErrEncrypted, so a
// caller that only wants to know "this response carried encrypted content this
// package could not accept" can test for that single sentinel.
var (
	// ErrNoDecryptionKey is returned when a response carries encrypted
	// content but neither Options.SPDecryptionKeys nor Options.SPSharedKeys
	// is configured. Encrypted content is never silently skipped.
	ErrNoDecryptionKey = fmt.Errorf("%w: no SP decryption key is configured (Options.SPDecryptionKeys or Options.SPSharedKeys)", ErrEncrypted)

	// ErrNoSharedKey is returned when an xenc:EncryptedData carries no
	// xenc:EncryptedKey — so it was encrypted directly under a key agreed out
	// of band — and no usable Options.SPSharedKeys entry is configured. It is
	// a rejection, never a fall-through to a weaker path.
	ErrNoSharedKey = fmt.Errorf("%w: the EncryptedData carries no xenc:EncryptedKey and no matching pre-shared symmetric key is configured (Options.SPSharedKeys)", ErrEncrypted)

	// ErrDecryptFailed is the single error every cryptographic failure path
	// returns: an unwrappable session key, a failed AEAD tag, bad CBC
	// padding, and — for CBC — a malformed or unparsable plaintext. They are
	// deliberately indistinguishable so that an attacker probing the ACS
	// endpoint learns nothing from the error they get back. See the
	// Options.AllowCBCDecryption documentation for the residual risk.
	ErrDecryptFailed = fmt.Errorf("%w: decryption failed", ErrEncrypted)

	// ErrDecryptedTooLarge is returned when decrypted plaintext exceeds
	// Options.MaxDecryptedBytes.
	ErrDecryptedTooLarge = fmt.Errorf("%w: decrypted content is too large", ErrEncrypted)
)

// defaultMaxDecryptedBytes caps the plaintext a single EncryptedData may expand
// into.
const defaultMaxDecryptedBytes = 1 << 20 // 1 MiB

// contentAlgorithm describes an AES content-encryption algorithm.
type contentAlgorithm struct {
	keyLen int  // AES key length in bytes
	gcm    bool // GCM (authenticated) rather than CBC
}

var contentAlgorithms = map[string]contentAlgorithm{
	AlgAES128GCM: {16, true},
	AlgAES192GCM: {24, true},
	AlgAES256GCM: {32, true},
	AlgAES128CBC: {16, false},
	AlgAES192CBC: {24, false},
	AlgAES256CBC: {32, false},
	// Triple-DES (#tripledes-cbc) is absent on purpose: a 64-bit block cipher
	// has a practical birthday bound and there is no reason to accept it.
}

// mgfAlgorithms maps XML Encryption 1.1 mask-generation-function URIs to their
// hash.
var mgfAlgorithms = map[string]crypto.Hash{
	nsXMLEnc11 + "mgf1sha1":   crypto.SHA1,
	nsXMLEnc11 + "mgf1sha224": crypto.SHA224,
	nsXMLEnc11 + "mgf1sha256": crypto.SHA256,
	nsXMLEnc11 + "mgf1sha384": crypto.SHA384,
	nsXMLEnc11 + "mgf1sha512": crypto.SHA512,
}

// newHashConstructor returns a hash.Hash factory for h.
//
// It is a switch rather than crypto.Hash.New so that an algorithm this package
// has not deliberately linked in cannot be reached by URI alone.
func newHashConstructor(h crypto.Hash) (func() hash.Hash, error) {
	switch h {
	case crypto.SHA1:
		return sha1.New, nil
	case crypto.SHA256:
		return sha256.New, nil
	case crypto.SHA384:
		return sha512.New384, nil
	case crypto.SHA512:
		return sha512.New, nil
	}
	return nil, fmt.Errorf("saml: unsupported hash %v", h)
}

// ParsePrivateKeys parses one or more concatenated PEM private-key blocks
// ("PRIVATE KEY" for PKCS#8, "RSA PRIVATE KEY" for PKCS#1, "EC PRIVATE KEY" for
// SEC 1). It is the helper behind Options.SPDecryptionKeyPEM and is exported so
// callers can validate their configuration at start-up.
//
// Encrypted (passphrase-protected) PEM blocks are rejected: the legacy
// PEM encryption they use is itself unsafe, and decrypting them is the
// application's job.
func ParsePrivateKeys(pemBytes []byte) ([]crypto.PrivateKey, error) {
	var out []crypto.PrivateKey
	rest := pemBytes
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if _, ok := block.Headers["DEK-Info"]; ok {
			return nil, errors.New("saml: encrypted PEM private keys are not supported; decrypt the key first")
		}
		var (
			key crypto.PrivateKey
			err error
		)
		switch block.Type {
		case "PRIVATE KEY":
			key, err = x509.ParsePKCS8PrivateKey(block.Bytes)
		case "RSA PRIVATE KEY":
			key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		case "EC PRIVATE KEY":
			key, err = x509.ParseECPrivateKey(block.Bytes)
		default:
			return nil, fmt.Errorf("saml: unexpected PEM block %q, want a PRIVATE KEY block", block.Type)
		}
		if err != nil {
			return nil, fmt.Errorf("saml: parsing SP decryption key: %w", err)
		}
		out = append(out, key)
	}
	if len(out) == 0 {
		return nil, errors.New("saml: no PRIVATE KEY block found in PEM input")
	}
	return out, nil
}

// decrypted is the plaintext of one EncryptedData together with the one bit of
// provenance the caller must not lose: whether an unauthenticated cipher mode
// produced it.
type decrypted struct {
	plaintext []byte
	// cbc reports that the content cipher was AES-CBC, which provides no
	// integrity. Every error raised while interpreting plaintext must then be
	// funnelled through mask, so that "the padding was wrong", "the bytes were
	// not XML" and "the XML was not an assertion" are one indistinguishable
	// outcome rather than three oracle responses.
	cbc bool
}

// mask collapses a downstream error into ErrDecryptFailed when the plaintext
// came from an unauthenticated cipher. For AES-GCM the tag already proves the
// ciphertext was produced by someone holding the session key, so no oracle
// exists and the specific error is returned unchanged.
func (d *decrypted) mask(err error) error {
	if err == nil || !d.cbc {
		return err
	}
	return ErrDecryptFailed
}

// hasDecryptionKey reports whether any key at all is configured that could open
// encrypted content: a private key for RSA key transport, or a pre-shared
// symmetric key. With none, encrypted content is rejected rather than skipped.
func (s *Strategy) hasDecryptionKey() bool {
	return len(s.spKeys) > 0 || len(s.sharedKeys) > 0
}

// decryptElement decrypts the xenc:EncryptedData inside container, which is a
// saml:EncryptedAssertion or saml:EncryptedID element.
//
// It performs no authentication of any kind. See the file comment.
func (s *Strategy) decryptElement(container *xnode) (*decrypted, error) {
	if !s.hasDecryptionKey() {
		return nil, ErrNoDecryptionKey
	}
	ed, err := container.onlyChild(nsXMLEnc, "EncryptedData")
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrEncrypted, err)
	}
	if typ, ok := ed.attrValue("", "Type"); ok && typ != "" && typ != nsXMLEnc+"Element" {
		// #Content decryption yields a node list rather than one element and
		// is not something SAML uses; refuse it rather than guess.
		return nil, fmt.Errorf("%w: unsupported EncryptedData Type %q", ErrEncrypted, typ)
	}

	// --- content algorithm ------------------------------------------------
	em, err := ed.onlyChild(nsXMLEnc, "EncryptionMethod")
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrEncrypted, err)
	}
	cAlgURI, _ := em.attrValue("", "Algorithm")
	cAlg, ok := contentAlgorithms[cAlgURI]
	if !ok {
		return nil, fmt.Errorf("%w: unsupported content encryption algorithm %q", ErrEncrypted, cAlgURI)
	}
	if !cAlg.gcm && !s.allowCBC {
		return nil, fmt.Errorf("%w: AES-CBC content encryption (%s) is refused; set Options.AllowCBCDecryption to accept it", ErrEncrypted, cAlgURI)
	}

	// --- content key ------------------------------------------------------
	//
	// Either an xenc:EncryptedKey carries the session key — the usual case,
	// wrapped to this SP's public key or to a shared KEK — or there is none,
	// which means the content was encrypted directly under a symmetric key
	// agreed out of band. In the latter case more than one candidate key may
	// have to be tried, so the resolution below always yields a list.
	ek, err := findEncryptedKey(container, ed)
	if err != nil {
		return nil, err
	}
	var contentKeys [][]byte
	if ek != nil {
		sessionKey, err := s.unwrapSessionKey(ek, cAlg.keyLen)
		if err != nil {
			return nil, err
		}
		contentKeys = [][]byte{sessionKey}
	} else {
		contentKeys, err = s.sharedKeyCandidates(ed, cAlg.keyLen, ErrNoSharedKey)
		if err != nil {
			return nil, err
		}
	}

	// --- ciphertext -------------------------------------------------------
	ciphertext, err := cipherValue(ed)
	if err != nil {
		return nil, err
	}
	// Reject before allocating: AES never expands, so a ciphertext bigger
	// than the plaintext cap can only ever decrypt to something over it.
	if len(ciphertext) > s.maxDecrypted+aes.BlockSize+16 {
		return nil, ErrDecryptedTooLarge
	}

	// Every candidate that fails yields the same ErrDecryptFailed, so which
	// key was tried — and whether any was even close — is not observable.
	var plaintext []byte
	found := false
	for _, k := range contentKeys {
		pt, err := decryptContent(cAlg, k, ciphertext)
		if err != nil {
			continue
		}
		plaintext, found = pt, true
		break
	}
	if !found {
		return nil, ErrDecryptFailed
	}
	d := &decrypted{plaintext: plaintext, cbc: !cAlg.gcm}
	if len(plaintext) > s.maxDecrypted {
		// Masked for CBC like every other post-decryption outcome: "the
		// padding was valid and the plaintext was long" is still a bit of
		// information about the plaintext.
		return nil, d.mask(ErrDecryptedTooLarge)
	}
	return d, nil
}

// findEncryptedKey locates the xenc:EncryptedKey carrying the session key. It
// may sit inside the EncryptedData's ds:KeyInfo, or — as ADFS and Shibboleth
// emit it — as a sibling of the EncryptedData inside the container.
//
// It returns (nil, nil) when there is none, which means the content was
// encrypted directly under a pre-shared symmetric key.
func findEncryptedKey(container, ed *xnode) (*xnode, error) {
	if ki, err := ed.optionalChild(nsDSig, "KeyInfo"); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrEncrypted, err)
	} else if ki != nil {
		if ek, err := ki.optionalChild(nsXMLEnc, "EncryptedKey"); err != nil {
			return nil, fmt.Errorf("%w: %v", ErrEncrypted, err)
		} else if ek != nil {
			return ek, nil
		}
	}
	ek, err := container.optionalChild(nsXMLEnc, "EncryptedKey")
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrEncrypted, err)
	}
	return ek, nil
}

// keyName reads the ds:KeyInfo/ds:KeyName of n, which is how a producer names
// which of several pre-shared keys it used. It returns "" when there is none.
func keyName(n *xnode) (string, error) {
	ki, err := n.optionalChild(nsDSig, "KeyInfo")
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrEncrypted, err)
	}
	if ki == nil {
		return "", nil
	}
	kn, err := ki.optionalChild(nsDSig, "KeyName")
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrEncrypted, err)
	}
	if kn == nil {
		return "", nil
	}
	return strings.TrimSpace(kn.textContent()), nil
}

// sharedKeyCandidates resolves the pre-shared symmetric keys of exactly keyLen
// bytes that may be tried for n, which is either the xenc:EncryptedData (the
// key is the content key) or an xenc:EncryptedKey (the key is a KEK).
//
// A ds:KeyName pins the choice to one configured key, which is what makes a
// rollover — two keys live at once — workable. With no ds:KeyName every
// configured key of the right length is a candidate and the caller tries each;
// the caller must report one identical failure for all of them, so the number
// of configured keys and which one nearly worked stay unobservable.
//
// none is the error reported when nothing usable is configured at all.
func (s *Strategy) sharedKeyCandidates(n *xnode, keyLen int, none error) ([][]byte, error) {
	name, err := keyName(n)
	if err != nil {
		return nil, err
	}
	if name != "" {
		key, ok := s.sharedKeys[name]
		if !ok {
			// Naming an unconfigured key is a configuration mismatch, not a
			// guess at the plaintext, so saying so is safe and actionable.
			return nil, fmt.Errorf("%w: no pre-shared key named %q is configured (Options.SPSharedKeys)", ErrEncrypted, name)
		}
		if len(key) != keyLen {
			return nil, fmt.Errorf("%w: pre-shared key %q is %d bytes but the algorithm needs %d", ErrEncrypted, name, len(key), keyLen)
		}
		return [][]byte{key}, nil
	}
	// Sorted so that the order keys are tried in is deterministic rather than
	// whatever the map happens to yield.
	names := make([]string, 0, len(s.sharedKeys))
	for k := range s.sharedKeys {
		names = append(names, k)
	}
	sort.Strings(names)
	var out [][]byte
	for _, k := range names {
		if len(s.sharedKeys[k]) == keyLen {
			out = append(out, s.sharedKeys[k])
		}
	}
	if len(out) == 0 {
		return nil, none
	}
	return out, nil
}

// cipherValue reads and base64-decodes an element's CipherData/CipherValue.
//
// A CipherReference — which points at a URI the processor is expected to
// dereference — is refused outright: honouring it would turn the ACS endpoint
// into a server-side request forgery gadget.
func cipherValue(n *xnode) ([]byte, error) {
	cd, err := n.onlyChild(nsXMLEnc, "CipherData")
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrEncrypted, err)
	}
	if ref, err := cd.optionalChild(nsXMLEnc, "CipherReference"); err == nil && ref != nil {
		return nil, fmt.Errorf("%w: xenc:CipherReference is not allowed", ErrEncrypted)
	}
	cv, err := cd.onlyChild(nsXMLEnc, "CipherValue")
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrEncrypted, err)
	}
	raw, err := decodeXMLBase64(cv.textContent())
	if err != nil {
		return nil, fmt.Errorf("%w: malformed CipherValue", ErrEncrypted)
	}
	return raw, nil
}

// unwrapSessionKey RSA-decrypts the wrapped content-encryption key, which must
// come out at exactly keyLen bytes.
//
// Every failure — wrong key, malformed ciphertext, wrong length — collapses to
// ErrDecryptFailed. Reporting them apart is exactly the oracle RSA key
// transport must not offer.
func (s *Strategy) unwrapSessionKey(ek *xnode, keyLen int) ([]byte, error) {
	em, err := ek.onlyChild(nsXMLEnc, "EncryptionMethod")
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrEncrypted, err)
	}
	alg, _ := em.attrValue("", "Algorithm")

	wrapped, err := cipherValue(ek)
	if err != nil {
		return nil, err
	}

	// AES-KeyWrap: the wrapping key is one of the pre-shared symmetric keys,
	// so this is the same trust situation as an EncryptedData with no
	// EncryptedKey at all — see Options.SPSharedKeys.
	if kekLen, ok := keyWrapAlgorithms[alg]; ok {
		keks, err := s.sharedKeyCandidates(ek, kekLen, fmt.Errorf(
			"%w: no pre-shared key of %d bytes is configured for %s (Options.SPSharedKeys)", ErrEncrypted, kekLen, alg))
		if err != nil {
			return nil, err
		}
		for _, kek := range keks {
			key, err := aesKeyUnwrap(kek, wrapped)
			if err == nil && len(key) == keyLen {
				return key, nil
			}
		}
		return nil, ErrDecryptFailed
	}

	var rsaKeys []*rsa.PrivateKey
	for _, k := range s.spKeys {
		if rk, ok := k.(*rsa.PrivateKey); ok {
			rsaKeys = append(rsaKeys, rk)
		}
	}
	if len(rsaKeys) == 0 {
		return nil, fmt.Errorf("%w: no RSA private key configured for key transport", ErrEncrypted)
	}

	switch alg {
	case AlgRSAOAEPMGF1P, AlgRSAOAEP:
		hashFn, label, err := oaepParameters(alg, em)
		if err != nil {
			return nil, err
		}
		for _, k := range rsaKeys {
			key, err := rsa.DecryptOAEP(hashFn(), rand.Reader, k, wrapped, label)
			if err == nil && len(key) == keyLen {
				return key, nil
			}
		}
		return nil, ErrDecryptFailed

	case AlgRSA15:
		if !s.allowRSA15 {
			return nil, fmt.Errorf("%w: RSA-PKCS#1 v1.5 key transport (%s) is refused; it is Bleichenbacher-attackable", ErrEncrypted, alg)
		}
		// DecryptPKCS1v15SessionKey is the constant-time form: on any
		// failure it leaves the caller-supplied random key in place instead
		// of signalling, which is what denies a Bleichenbacher oracle. The
		// resulting garbage key then simply fails to produce usable
		// plaintext.
		for _, k := range rsaKeys {
			key := make([]byte, keyLen)
			if _, err := rand.Read(key); err != nil {
				return nil, err
			}
			if err := rsa.DecryptPKCS1v15SessionKey(rand.Reader, k, wrapped, key); err != nil {
				continue
			}
			return key, nil
		}
		return nil, ErrDecryptFailed

	default:
		return nil, fmt.Errorf("%w: unsupported key transport algorithm %q", ErrEncrypted, alg)
	}
}

// aesKeyWrapIV is the default initial value of RFC 3394, section 2.2.3.1. On
// unwrap it is the integrity check: recovering it proves the unwrapper holds
// the same KEK the wrapper used.
var aesKeyWrapIV = []byte{0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6}

// aesKeyUnwrap implements the RFC 3394 AES Key Unwrap index-based algorithm
// (section 2.2.2). wrapped is 8 bytes longer than the key it carries, and the
// key must be a whole number of 64-bit blocks, at least two of them.
//
// Every failure — a malformed length, an unusable KEK, a failed integrity
// check — is one indistinguishable ErrDecryptFailed, for the same reason the
// RSA unwrap above collapses its failures.
func aesKeyUnwrap(kek, wrapped []byte) ([]byte, error) {
	if len(wrapped) < 24 || len(wrapped)%8 != 0 {
		return nil, ErrDecryptFailed
	}
	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, ErrDecryptFailed
	}
	n := len(wrapped)/8 - 1

	a := make([]byte, 8)
	copy(a, wrapped[:8])
	r := make([]byte, len(wrapped)-8)
	copy(r, wrapped[8:])

	buf := make([]byte, 16)
	for j := 5; j >= 0; j-- {
		for i := n; i >= 1; i-- {
			// B = AES-1( (A ^ t) | R[i] ), with t = n*j + i encoded big-endian
			// in the low 64 bits.
			t := uint64(n*j + i)
			copy(buf[:8], a)
			for k := 0; k < 8; k++ {
				buf[7-k] ^= byte(t >> (8 * k))
			}
			copy(buf[8:], r[(i-1)*8:i*8])
			block.Decrypt(buf, buf)
			copy(a, buf[:8])
			copy(r[(i-1)*8:i*8], buf[8:])
		}
	}
	if subtle.ConstantTimeCompare(a, aesKeyWrapIV) != 1 {
		return nil, ErrDecryptFailed
	}
	return r, nil
}

// oaepParameters resolves the digest, mask-generation function and optional
// label of an RSA-OAEP EncryptionMethod.
func oaepParameters(alg string, em *xnode) (func() hash.Hash, []byte, error) {
	digest := crypto.SHA1 // the xmlenc default for both OAEP URIs
	if dm, err := em.optionalChild(nsDSig, "DigestMethod"); err != nil {
		return nil, nil, fmt.Errorf("%w: %v", ErrEncrypted, err)
	} else if dm != nil {
		uri, _ := dm.attrValue("", "Algorithm")
		d, ok := digestAlgorithms[uri]
		if !ok {
			return nil, nil, fmt.Errorf("%w: unsupported OAEP digest %q", ErrEncrypted, uri)
		}
		digest = d.hash
	}

	// SHA-1 is accepted here and nowhere else in this package. OAEP relies on
	// the hash as a random oracle, not on collision resistance, so SHA-1's
	// collision breaks do not apply; and #rsa-oaep-mgf1p pins MGF1-SHA1 by
	// definition, so refusing it would refuse the algorithm every deployed
	// identity provider actually emits.
	mgf := crypto.SHA1
	if alg == AlgRSAOAEP {
		if m, err := em.optionalChild(nsXMLEnc11, "MGF"); err != nil {
			return nil, nil, fmt.Errorf("%w: %v", ErrEncrypted, err)
		} else if m != nil {
			uri, _ := m.attrValue("", "Algorithm")
			h, ok := mgfAlgorithms[uri]
			if !ok {
				return nil, nil, fmt.Errorf("%w: unsupported MGF %q", ErrEncrypted, uri)
			}
			mgf = h
		} else {
			// XML Encryption 1.1 defaults #rsa-oaep to MGF1-SHA1, but every
			// producer that uses the 1.1 URI states it explicitly, and
			// pairing it with a SHA-256 digest is the common case. Track the
			// digest so that the usual configuration works.
			mgf = digest
		}
	}
	if mgf != digest {
		// crypto/rsa derives the MGF from the same hash it uses for the
		// label, so a mismatched pair cannot be expressed. Refusing is
		// correct; silently using one hash for both would produce a wrong
		// answer, not a weaker one.
		return nil, nil, fmt.Errorf("%w: OAEP digest %v and MGF %v differ, which crypto/rsa cannot express", ErrEncrypted, digest, mgf)
	}

	hashFn, err := newHashConstructor(digest)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %v", ErrEncrypted, err)
	}

	var label []byte
	if p, err := em.optionalChild(nsXMLEnc, "OAEPparams"); err != nil {
		return nil, nil, fmt.Errorf("%w: %v", ErrEncrypted, err)
	} else if p != nil {
		if text := strings.TrimSpace(p.textContent()); text != "" {
			label, err = decodeXMLBase64(text)
			if err != nil {
				return nil, nil, fmt.Errorf("%w: malformed OAEPparams", ErrEncrypted)
			}
		}
	}
	return hashFn, label, nil
}

// decryptContent decrypts an XML Encryption content ciphertext, which carries
// its IV as a prefix.
func decryptContent(alg contentAlgorithm, key, ciphertext []byte) ([]byte, error) {
	if len(key) != alg.keyLen {
		return nil, ErrDecryptFailed
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, ErrDecryptFailed
	}
	if alg.gcm {
		aead, err := cipher.NewGCM(block)
		if err != nil {
			return nil, ErrDecryptFailed
		}
		// XML Encryption 1.1 fixes the AES-GCM IV at 96 bits and appends the
		// 128-bit tag to the ciphertext, which is exactly what crypto/cipher's
		// GCM expects once the nonce is split off.
		ns := aead.NonceSize()
		if len(ciphertext) < ns+aead.Overhead() {
			return nil, ErrDecryptFailed
		}
		out, err := aead.Open(nil, ciphertext[:ns], ciphertext[ns:], nil)
		if err != nil {
			return nil, ErrDecryptFailed
		}
		return out, nil
	}
	return decryptCBC(block, ciphertext)
}

// decryptCBC decrypts AES-CBC content and strips the ISO 10126 padding XML
// Encryption specifies (the final byte gives the padding length; the preceding
// filler bytes are arbitrary).
//
// Padding validation is done branch-free and the caller masks every downstream
// error, because this mode is the Jager–Somorovsky padding oracle target. See
// Options.AllowCBCDecryption for the residual risk that remains.
func decryptCBC(block cipher.Block, ciphertext []byte) ([]byte, error) {
	bs := block.BlockSize()
	if len(ciphertext) < 2*bs || len(ciphertext)%bs != 0 {
		return nil, ErrDecryptFailed
	}
	iv := ciphertext[:bs]
	body := make([]byte, len(ciphertext)-bs)
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(body, ciphertext[bs:])

	pad := int(body[len(body)-1])
	// good = (1 <= pad) && (pad <= bs) && (pad <= len(body)), computed without
	// branching on the plaintext.
	good := subtle.ConstantTimeLessOrEq(1, pad) &
		subtle.ConstantTimeLessOrEq(pad, bs) &
		subtle.ConstantTimeLessOrEq(pad, len(body))
	// Select a length that is always in range so the slice below cannot panic
	// on the bad path; the result is discarded either way.
	n := subtle.ConstantTimeSelect(good, len(body)-pad, 0)
	if good != 1 {
		return nil, ErrDecryptFailed
	}
	return body[:n], nil
}
