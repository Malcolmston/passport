// Package webauthn implements WebAuthn (passkey / FIDO2) authentication for
// passport. It provides both ceremony halves — registration and authentication —
// and a passport.Strategy that verifies a login assertion. It is the Go
// counterpart to the passkey/WebAuthn strategies in the Passport.js ecosystem,
// built entirely on the standard library (crypto, plus a small CBOR decoder) with
// no external dependencies.
//
// Reach for this package to offer passkeys: phishing-resistant, public-key
// credentials that let users sign in with a platform authenticator (Touch ID,
// Windows Hello, Android biometrics) or a roaming security key instead of a
// password. Passkeys are a strong primary factor and a natural passwordless
// replacement for username/password login, as well as a hardware-backed second
// factor. Unlike the OAuth presets in this library there is no third-party
// identity provider — your own site is the relying party and holds the registered
// public keys.
//
// WebAuthn works as a pair of challenge-response "ceremonies" driven by the
// browser's navigator.credentials API. To register, the server calls
// BeginRegistration to mint a random challenge and creation options; the browser
// runs navigator.credentials.create(), and the server verifies the result with
// FinishRegistration, persisting the returned Credential (its id, COSE public key,
// AAGUID, and signature counter). To authenticate, the server calls
// BeginAuthentication to mint a fresh challenge and request options; the browser
// runs navigator.credentials.get() and POSTs the assertion, which the Strategy
// verifies. In both ceremonies the raw challenge must be stored server-side
// (typically in the session) and returned during verification via the
// ChallengeFunc.
//
// Verification scope and semantics: the authentication ceremony is fully verified —
// the client-data type, challenge, and origin; the RP ID hash; the user-presence
// flag; the assertion signature (ES256 / ECDSA-P256 or RS256); and the signature
// counter for cloned-authenticator detection (the counter must strictly increase
// when either side is non-zero). A Store resolves a credential id to the owning
// user and stored Credential; implement the optional SignCountUpdater to persist
// the advancing counter. Registration parses the attestation object and extracts
// the credential public key, but attestation *statement* verification (proving the
// authenticator's make/model) is treated as "none" — the common, privacy-preserving
// default for consumer passkeys. Configure the relying party via Config (RPID,
// RPOrigin, RPName); an empty RPOrigin skips the origin check and should be set in
// production.
//
// Parity note: this package covers the mainstream passkey flows rather than the
// full breadth of the FIDO2/WebAuthn specification. It supports the two most common
// algorithms (ES256 and RS256), assumes attestation "none", and leaves credential
// storage, session handling, and enrollment policy to the application. If you need
// packed/TPM/android-key attestation verification or additional COSE algorithms,
// extend the verification path accordingly.
package webauthn

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"math/big"
)

// Config describes the relying party (your site).
type Config struct {
	// RPID is the relying party identifier — usually the site's domain
	// (e.g. "example.com").
	RPID string
	// RPOrigin is the expected origin of ceremonies
	// (e.g. "https://example.com").
	RPOrigin string
	// RPName is a human-readable relying party name.
	RPName string
}

// Credential is a registered public-key credential to be persisted by the
// application and looked up during authentication.
type Credential struct {
	// ID is the raw credential id.
	ID []byte
	// PublicKey is the parsed COSE public key (*ecdsa.PublicKey or
	// *rsa.PublicKey).
	PublicKey crypto.PublicKey
	// AAGUID identifies the authenticator model.
	AAGUID []byte
	// SignCount is the signature counter from registration.
	SignCount uint32
	// COSEAlg is the COSE algorithm identifier (e.g. -7 for ES256, -257 RS256).
	COSEAlg int64
}

// authenticatorData is the parsed authenticator data structure.
type authenticatorData struct {
	rpIDHash  []byte
	flags     byte
	signCount uint32
	aaguid    []byte
	credID    []byte
	credKey   crypto.PublicKey
	coseAlg   int64
	rawLength int
}

const (
	flagUserPresent   = 0x01
	flagUserVerified  = 0x04
	flagAttestedCred  = 0x40
	flagHasExtensions = 0x80
)

var (
	// ErrBadAttestation indicates a malformed attestation object.
	ErrBadAttestation = errors.New("webauthn: malformed attestation object")
	// ErrUnsupportedKey indicates an unsupported COSE key type/algorithm.
	ErrUnsupportedKey = errors.New("webauthn: unsupported public key algorithm")
	// ErrVerification indicates a failed assertion verification.
	ErrVerification = errors.New("webauthn: verification failed")
)

// parseAuthData parses authenticator data. When expectCred is true it also
// parses attested credential data (present during registration).
func parseAuthData(data []byte) (*authenticatorData, error) {
	if len(data) < 37 {
		return nil, ErrBadAttestation
	}
	ad := &authenticatorData{
		rpIDHash:  data[:32],
		flags:     data[32],
		signCount: binary.BigEndian.Uint32(data[33:37]),
	}
	off := 37
	if ad.flags&flagAttestedCred != 0 {
		if len(data) < off+18 {
			return nil, ErrBadAttestation
		}
		ad.aaguid = data[off : off+16]
		credLen := int(binary.BigEndian.Uint16(data[off+16 : off+18]))
		off += 18
		if len(data) < off+credLen {
			return nil, ErrBadAttestation
		}
		ad.credID = data[off : off+credLen]
		off += credLen
		// The remaining bytes begin with the COSE public key (CBOR map).
		key, consumed, alg, err := parseCOSEKey(data[off:])
		if err != nil {
			return nil, err
		}
		ad.credKey = key
		ad.coseAlg = alg
		off += consumed
	}
	ad.rawLength = off
	return ad, nil
}

// parseCOSEKey decodes a COSE_Key (CBOR map) into a crypto.PublicKey.
func parseCOSEKey(data []byte) (crypto.PublicKey, int, int64, error) {
	v, n, err := cborDecode(data)
	if err != nil {
		return nil, 0, 0, err
	}
	m, ok := v.(map[any]any)
	if !ok {
		return nil, 0, 0, ErrUnsupportedKey
	}
	kty, _ := asInt(m[int64(1)])
	alg, _ := asInt(m[int64(3)])

	switch kty {
	case 2: // EC2
		x, xok := m[int64(-2)].([]byte)
		y, yok := m[int64(-3)].([]byte)
		if !xok || !yok {
			return nil, 0, 0, ErrUnsupportedKey
		}
		crv, _ := asInt(m[int64(-1)])
		curve := elliptic.P256()
		if crv != 1 { // 1 = P-256
			return nil, 0, 0, ErrUnsupportedKey
		}
		pub := &ecdsa.PublicKey{
			Curve: curve,
			X:     new(big.Int).SetBytes(x),
			Y:     new(big.Int).SetBytes(y),
		}
		return pub, n, alg, nil
	case 3: // RSA
		nBytes, nok := m[int64(-1)].([]byte)
		eBytes, eok := m[int64(-2)].([]byte)
		if !nok || !eok {
			return nil, 0, 0, ErrUnsupportedKey
		}
		e := 0
		for _, b := range eBytes {
			e = e<<8 | int(b)
		}
		pub := &rsa.PublicKey{N: new(big.Int).SetBytes(nBytes), E: e}
		return pub, n, alg, nil
	default:
		return nil, 0, 0, ErrUnsupportedKey
	}
}

// FinishRegistration parses a registration response's attestation object and
// clientDataJSON, verifies the challenge and origin, and returns the credential
// to persist. attestationObject and clientDataJSON are the raw (base64url-
// decoded) bytes.
func (c *Config) FinishRegistration(attestationObject, clientDataJSON, expectedChallenge []byte) (*Credential, error) {
	if err := c.verifyClientData(clientDataJSON, "webauthn.create", expectedChallenge); err != nil {
		return nil, err
	}

	v, _, err := cborDecode(attestationObject)
	if err != nil {
		return nil, ErrBadAttestation
	}
	m, ok := v.(map[any]any)
	if !ok {
		return nil, ErrBadAttestation
	}
	authDataRaw, ok := m["authData"].([]byte)
	if !ok {
		return nil, ErrBadAttestation
	}
	ad, err := parseAuthData(authDataRaw)
	if err != nil {
		return nil, err
	}
	if ad.flags&flagAttestedCred == 0 || ad.credKey == nil {
		return nil, ErrBadAttestation
	}
	// Verify the RP ID hash.
	if !bytesEqual(ad.rpIDHash, rpIDHash(c.RPID)) {
		return nil, ErrVerification
	}
	if ad.flags&flagUserPresent == 0 {
		return nil, ErrVerification
	}
	return &Credential{
		ID:        ad.credID,
		PublicKey: ad.credKey,
		AAGUID:    ad.aaguid,
		SignCount: ad.signCount,
		COSEAlg:   ad.coseAlg,
	}, nil
}

func rpIDHash(rpID string) []byte {
	h := sha256.Sum256([]byte(rpID))
	return h[:]
}

func asInt(v any) (int64, bool) {
	switch n := v.(type) {
	case int64:
		return n, true
	case int:
		return int64(n), true
	default:
		return 0, false
	}
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
