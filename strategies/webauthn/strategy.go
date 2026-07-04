package webauthn

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"github.com/malcolmston/passport"
)

// Store looks up a registered credential by its id and returns the associated
// user. Implementations back this with a database.
type Store interface {
	Get(credentialID []byte) (user any, cred *Credential, err error)
}

// SignCountUpdater is an optional Store extension: when implemented, the
// strategy reports the new signature counter after a successful assertion so it
// can be persisted (clone-detection).
type SignCountUpdater interface {
	UpdateSignCount(credentialID []byte, newCount uint32) error
}

// ChallengeFunc returns the challenge expected for this request (typically read
// from the user's session where BeginAuthentication stored it).
type ChallengeFunc func(r *http.Request) []byte

// Strategy authenticates a WebAuthn assertion.
type Strategy struct {
	cfg       Config
	store     Store
	challenge ChallengeFunc
}

// New creates a WebAuthn authentication strategy.
func New(cfg Config, store Store, challenge ChallengeFunc) *Strategy {
	return &Strategy{cfg: cfg, store: store, challenge: challenge}
}

// Name returns "webauthn".
func (s *Strategy) Name() string { return "webauthn" }

// authResponse mirrors the JSON produced by a browser's
// navigator.credentials.get() (with binary fields base64url-encoded).
type authResponse struct {
	ID       string `json:"id"`
	RawID    string `json:"rawId"`
	Type     string `json:"type"`
	Response struct {
		ClientDataJSON    string `json:"clientDataJSON"`
		AuthenticatorData string `json:"authenticatorData"`
		Signature         string `json:"signature"`
		UserHandle        string `json:"userHandle"`
	} `json:"response"`
}

// Authenticate implements passport.Strategy.
func (s *Strategy) Authenticate(c *passport.Context, r *http.Request) {
	data, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		c.Error(err)
		return
	}
	var resp authResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		c.Fail("invalid assertion", http.StatusBadRequest)
		return
	}

	credID, err := b64decode(firstNonEmpty(resp.RawID, resp.ID))
	if err != nil {
		c.Fail("invalid credential id", http.StatusBadRequest)
		return
	}
	clientDataJSON, err1 := b64decode(resp.Response.ClientDataJSON)
	authData, err2 := b64decode(resp.Response.AuthenticatorData)
	sig, err3 := b64decode(resp.Response.Signature)
	if err1 != nil || err2 != nil || err3 != nil {
		c.Fail("malformed assertion", http.StatusBadRequest)
		return
	}

	user, cred, err := s.store.Get(credID)
	if err != nil {
		c.Error(err)
		return
	}
	if user == nil || cred == nil {
		c.Fail("unknown credential", http.StatusUnauthorized)
		return
	}

	expectedChallenge := s.challenge(r)
	if err := s.cfg.verifyClientData(clientDataJSON, "webauthn.get", expectedChallenge); err != nil {
		c.Fail("challenge/origin mismatch", http.StatusUnauthorized)
		return
	}

	ad, err := parseAuthData(authData)
	if err != nil {
		c.Fail("bad authenticator data", http.StatusUnauthorized)
		return
	}
	if !bytesEqual(ad.rpIDHash, rpIDHash(s.cfg.RPID)) {
		c.Fail("rp id mismatch", http.StatusUnauthorized)
		return
	}
	if ad.flags&flagUserPresent == 0 {
		c.Fail("user not present", http.StatusUnauthorized)
		return
	}

	if err := verifyAssertionSignature(cred, authData, clientDataJSON, sig); err != nil {
		c.Fail("signature verification failed", http.StatusUnauthorized)
		return
	}

	// Clone-detection: the counter must strictly increase when either side is
	// non-zero.
	if ad.signCount != 0 || cred.SignCount != 0 {
		if ad.signCount <= cred.SignCount {
			c.Fail("possible cloned authenticator", http.StatusUnauthorized)
			return
		}
	}
	if u, ok := s.store.(SignCountUpdater); ok {
		_ = u.UpdateSignCount(credID, ad.signCount)
	}

	c.Success(user, map[string]any{"signCount": ad.signCount})
}

// clientData is the parsed clientDataJSON.
type clientData struct {
	Type      string `json:"type"`
	Challenge string `json:"challenge"`
	Origin    string `json:"origin"`
}

// verifyClientData checks the type, challenge, and origin of a clientDataJSON.
func (c *Config) verifyClientData(clientDataJSON []byte, expectedType string, expectedChallenge []byte) error {
	var cd clientData
	if err := json.Unmarshal(clientDataJSON, &cd); err != nil {
		return ErrVerification
	}
	if cd.Type != expectedType {
		return ErrVerification
	}
	// The challenge in clientData is base64url (no padding) of the raw bytes.
	if cd.Challenge != base64.RawURLEncoding.EncodeToString(expectedChallenge) {
		return ErrVerification
	}
	if c.RPOrigin != "" && cd.Origin != c.RPOrigin {
		return ErrVerification
	}
	return nil
}

// verifyAssertionSignature verifies the assertion signature over
// authenticatorData || SHA-256(clientDataJSON).
func verifyAssertionSignature(cred *Credential, authData, clientDataJSON, sig []byte) error {
	clientHash := sha256.Sum256(clientDataJSON)
	signed := make([]byte, 0, len(authData)+len(clientHash))
	signed = append(signed, authData...)
	signed = append(signed, clientHash[:]...)
	digest := sha256.Sum256(signed)

	switch pub := cred.PublicKey.(type) {
	case *ecdsa.PublicKey:
		if ecdsa.VerifyASN1(pub, digest[:], sig) {
			return nil
		}
		return ErrVerification
	case *rsa.PublicKey:
		if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], sig); err == nil {
			return nil
		}
		return ErrVerification
	default:
		return ErrUnsupportedKey
	}
}

// ---- ceremony option builders ----------------------------------------------

// NewChallenge returns 32 cryptographically-random challenge bytes.
func NewChallenge() ([]byte, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return b, nil
}

// BeginRegistration builds PublicKeyCredentialCreationOptions for the browser.
// It returns the raw challenge (store it in the session) and the JSON-friendly
// options (binary fields are base64url strings).
func (c *Config) BeginRegistration(userID, userName, displayName string) ([]byte, map[string]any, error) {
	challenge, err := NewChallenge()
	if err != nil {
		return nil, nil, err
	}
	options := map[string]any{
		"challenge": base64.RawURLEncoding.EncodeToString(challenge),
		"rp":        map[string]any{"id": c.RPID, "name": c.RPName},
		"user": map[string]any{
			"id":          base64.RawURLEncoding.EncodeToString([]byte(userID)),
			"name":        userName,
			"displayName": displayName,
		},
		"pubKeyCredParams": []map[string]any{
			{"type": "public-key", "alg": -7},   // ES256
			{"type": "public-key", "alg": -257}, // RS256
		},
		"timeout":     60000,
		"attestation": "none",
	}
	return challenge, options, nil
}

// BeginAuthentication builds PublicKeyCredentialRequestOptions for the browser.
func (c *Config) BeginAuthentication(allowCredentialIDs [][]byte) ([]byte, map[string]any, error) {
	challenge, err := NewChallenge()
	if err != nil {
		return nil, nil, err
	}
	allow := make([]map[string]any, 0, len(allowCredentialIDs))
	for _, id := range allowCredentialIDs {
		allow = append(allow, map[string]any{
			"type": "public-key",
			"id":   base64.RawURLEncoding.EncodeToString(id),
		})
	}
	options := map[string]any{
		"challenge":        base64.RawURLEncoding.EncodeToString(challenge),
		"rpId":             c.RPID,
		"timeout":          60000,
		"userVerification": "preferred",
		"allowCredentials": allow,
	}
	return challenge, options, nil
}

// b64decode decodes base64url (with or without padding) or standard base64.
func b64decode(s string) ([]byte, error) {
	if s == "" {
		return nil, errors.New("empty")
	}
	for _, enc := range []*base64.Encoding{
		base64.RawURLEncoding, base64.URLEncoding, base64.RawStdEncoding, base64.StdEncoding,
	} {
		if b, err := enc.DecodeString(s); err == nil {
			return b, nil
		}
	}
	return nil, errors.New("webauthn: invalid base64")
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
