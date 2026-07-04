package webauthn

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/malcolmston/passport"
)

// ---- tiny CBOR encoder for building test attestation data -------------------

func cuint(major byte, n uint64) []byte {
	h := major << 5
	switch {
	case n < 24:
		return []byte{h | byte(n)}
	case n < 256:
		return []byte{h | 24, byte(n)}
	case n < 65536:
		return []byte{h | 25, byte(n >> 8), byte(n)}
	case n < 1<<32:
		b := make([]byte, 5)
		b[0] = h | 26
		binary.BigEndian.PutUint32(b[1:], uint32(n))
		return b
	default:
		b := make([]byte, 9)
		b[0] = h | 27
		binary.BigEndian.PutUint64(b[1:], n)
		return b
	}
}

func cint(n int64) []byte {
	if n >= 0 {
		return cuint(0, uint64(n))
	}
	return cuint(1, uint64(-1-n))
}
func cbytes(b []byte) []byte { return append(cuint(2, uint64(len(b))), b...) }
func ctext(s string) []byte  { return append(cuint(3, uint64(len(s))), []byte(s)...) }
func cpair(k, v []byte) []byte {
	return append(append([]byte{}, k...), v...)
}
func cmap(pairs ...[]byte) []byte {
	out := cuint(5, uint64(len(pairs)))
	for _, p := range pairs {
		out = append(out, p...)
	}
	return out
}

func pad32(b []byte) []byte {
	if len(b) >= 32 {
		return b[len(b)-32:]
	}
	out := make([]byte, 32)
	copy(out[32-len(b):], b)
	return out
}

// coseKey builds a COSE_Key CBOR map for an ES256 public key.
func coseKey(pub *ecdsa.PublicKey) []byte {
	return cmap(
		cpair(cint(1), cint(2)),                       // kty: EC2
		cpair(cint(3), cint(-7)),                      // alg: ES256
		cpair(cint(-1), cint(1)),                      // crv: P-256
		cpair(cint(-2), cbytes(pad32(pub.X.Bytes()))), // x
		cpair(cint(-3), cbytes(pad32(pub.Y.Bytes()))), // y
	)
}

// authData assembles authenticator data.
func makeAuthData(rpID string, flags byte, signCount uint32, credID, cose []byte) []byte {
	h := sha256.Sum256([]byte(rpID))
	out := append([]byte{}, h[:]...)
	out = append(out, flags)
	sc := make([]byte, 4)
	binary.BigEndian.PutUint32(sc, signCount)
	out = append(out, sc...)
	if flags&flagAttestedCred != 0 {
		out = append(out, make([]byte, 16)...) // aaguid
		l := make([]byte, 2)
		binary.BigEndian.PutUint16(l, uint16(len(credID)))
		out = append(out, l...)
		out = append(out, credID...)
		out = append(out, cose...)
	}
	return out
}

func b64url(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func clientDataJSON(typ, origin string, challenge []byte) []byte {
	m := map[string]any{"type": typ, "challenge": b64url(challenge), "origin": origin}
	b, _ := json.Marshal(m)
	return b
}

// ---- the test ----------------------------------------------------------------

const (
	testRPID    = "example.com"
	testOrigin  = "https://example.com"
	testCredStr = "cred-1234"
)

func TestRegistrationAndAuthentication(t *testing.T) {
	cfg := Config{RPID: testRPID, RPOrigin: testOrigin, RPName: "Example"}

	// Simulate an authenticator with an ES256 key.
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	credID := []byte(testCredStr)
	cose := coseKey(&priv.PublicKey)

	// --- Registration ceremony ---
	regChallenge, _, err := cfg.BeginRegistration("user-1", "ada", "Ada L.")
	if err != nil {
		t.Fatal(err)
	}
	regAuthData := makeAuthData(testRPID, flagUserPresent|flagAttestedCred, 0, credID, cose)
	attObj := cmap(
		cpair(ctext("fmt"), ctext("none")),
		cpair(ctext("attStmt"), cmap()),
		cpair(ctext("authData"), cbytes(regAuthData)),
	)
	regClientData := clientDataJSON("webauthn.create", testOrigin, regChallenge)

	cred, err := cfg.FinishRegistration(attObj, regClientData, regChallenge)
	if err != nil {
		t.Fatalf("FinishRegistration: %v", err)
	}
	if string(cred.ID) != testCredStr {
		t.Fatalf("credential id = %q", cred.ID)
	}
	pub, ok := cred.PublicKey.(*ecdsa.PublicKey)
	if !ok || pub.X.Cmp(priv.PublicKey.X) != 0 || pub.Y.Cmp(priv.PublicKey.Y) != 0 {
		t.Fatal("registered public key does not match the authenticator key")
	}

	// --- Authentication ceremony ---
	store := &memStore{user: "ada@example.com", cred: cred}
	authChallenge, _, _ := cfg.BeginAuthentication([][]byte{credID})
	strat := New(cfg, store, func(r *http.Request) []byte { return authChallenge })

	assertion := signAssertion(t, priv, testRPID, testOrigin, authChallenge, credID, 1)

	c := &passport.Context{}
	req, _ := http.NewRequest("POST", "/login", strings.NewReader(assertion))
	strat.Authenticate(c, req)

	if c.Result() != passport.ResultSuccess {
		t.Fatalf("expected success, got %v (%v)", c.Result(), c.Err())
	}
	if c.SuccessUser() != "ada@example.com" {
		t.Fatalf("user = %v", c.SuccessUser())
	}
}

func TestAuthenticationRejectsBadSignature(t *testing.T) {
	cfg := Config{RPID: testRPID, RPOrigin: testOrigin}
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	credID := []byte("c")
	// The stored credential uses `other`'s public key, but the assertion is
	// signed with `priv` -> signature must fail.
	cred := &Credential{ID: credID, PublicKey: &other.PublicKey}
	store := &memStore{user: "x", cred: cred}
	challenge, _ := NewChallenge()
	strat := New(cfg, store, func(r *http.Request) []byte { return challenge })

	assertion := signAssertion(t, priv, testRPID, testOrigin, challenge, credID, 1)
	c := &passport.Context{}
	req, _ := http.NewRequest("POST", "/", strings.NewReader(assertion))
	strat.Authenticate(c, req)
	if c.Result() != passport.ResultFail {
		t.Fatalf("expected fail on bad signature, got %v", c.Result())
	}
}

func TestAuthenticationRejectsWrongOrigin(t *testing.T) {
	cfg := Config{RPID: testRPID, RPOrigin: testOrigin}
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	credID := []byte("c")
	cred := &Credential{ID: credID, PublicKey: &priv.PublicKey}
	store := &memStore{user: "x", cred: cred}
	challenge, _ := NewChallenge()
	strat := New(cfg, store, func(r *http.Request) []byte { return challenge })

	// Signed with a different origin than the RP expects.
	assertion := signAssertion(t, priv, testRPID, "https://evil.com", challenge, credID, 1)
	c := &passport.Context{}
	req, _ := http.NewRequest("POST", "/", strings.NewReader(assertion))
	strat.Authenticate(c, req)
	if c.Result() != passport.ResultFail {
		t.Fatalf("expected fail on wrong origin, got %v", c.Result())
	}
}

// signAssertion builds a signed navigator.credentials.get()-style JSON payload.
func signAssertion(t *testing.T, priv *ecdsa.PrivateKey, rpID, origin string, challenge, credID []byte, signCount uint32) string {
	t.Helper()
	authData := makeAuthData(rpID, flagUserPresent, signCount, nil, nil)
	cd := clientDataJSON("webauthn.get", origin, challenge)
	clientHash := sha256.Sum256(cd)
	signed := append(append([]byte{}, authData...), clientHash[:]...)
	digest := sha256.Sum256(signed)
	sig, err := ecdsa.SignASN1(rand.Reader, priv, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	resp := map[string]any{
		"id":    b64url(credID),
		"rawId": b64url(credID),
		"type":  "public-key",
		"response": map[string]any{
			"clientDataJSON":    b64url(cd),
			"authenticatorData": b64url(authData),
			"signature":         b64url(sig),
		},
	}
	b, _ := json.Marshal(resp)
	return string(b)
}

type memStore struct {
	user any
	cred *Credential
}

func (m *memStore) Get(id []byte) (any, *Credential, error) {
	if string(id) == string(m.cred.ID) {
		return m.user, m.cred, nil
	}
	return nil, nil, nil
}
