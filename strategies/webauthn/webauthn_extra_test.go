package webauthn

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"math"
	"math/big"
	"net/http"
	"strings"
	"testing"

	"github.com/malcolmston/passport"
)

func generateES256(t *testing.T) (*ecdsa.PrivateKey, *ecdsa.PublicKey) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return priv, &priv.PublicKey
}

func pubOf(priv *ecdsa.PrivateKey) crypto.PublicKey { return &priv.PublicKey }

func coseKeyOf(priv *ecdsa.PrivateKey) []byte { return coseKey(&priv.PublicKey) }

// ---- helpers ----------------------------------------------------------------

type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, errors.New("boom") }

// errStore returns an error from Get.
type errStore struct{}

func (errStore) Get([]byte) (any, *Credential, error) { return nil, nil, errors.New("db fail") }

// updaterStore records UpdateSignCount calls.
type updaterStore struct {
	user   any
	cred   *Credential
	newCnt uint32
	called bool
}

func (m *updaterStore) Get(id []byte) (any, *Credential, error) {
	if string(id) == string(m.cred.ID) {
		return m.user, m.cred, nil
	}
	return nil, nil, nil
}

func (m *updaterStore) UpdateSignCount(id []byte, n uint32) error {
	m.called = true
	m.newCnt = n
	return nil
}

func coseKeyRSA(pub *rsa.PublicKey) []byte {
	eb := big.NewInt(int64(pub.E)).Bytes()
	return cmap(
		cpair(cint(1), cint(3)),    // kty: RSA
		cpair(cint(3), cint(-257)), // alg: RS256
		cpair(cint(-1), cbytes(pub.N.Bytes())),
		cpair(cint(-2), cbytes(eb)),
	)
}

func signAssertionRSA(t *testing.T, priv *rsa.PrivateKey, rpID, origin string, challenge, credID []byte, signCount uint32) string {
	t.Helper()
	authData := makeAuthData(rpID, flagUserPresent, signCount, nil, nil)
	cd := clientDataJSON("webauthn.get", origin, challenge)
	clientHash := sha256.Sum256(cd)
	signed := append(append([]byte{}, authData...), clientHash[:]...)
	digest := sha256.Sum256(signed)
	sig, err := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	resp := map[string]any{
		"id": b64url(credID), "rawId": b64url(credID), "type": "public-key",
		"response": map[string]any{
			"clientDataJSON":    b64url(cd),
			"authenticatorData": b64url(authData),
			"signature":         b64url(sig),
		},
	}
	b, _ := json.Marshal(resp)
	return string(b)
}

func buildResp(credID, cd, authData, sig []byte) string {
	resp := map[string]any{
		"id": b64url(credID), "rawId": b64url(credID), "type": "public-key",
		"response": map[string]any{
			"clientDataJSON":    b64url(cd),
			"authenticatorData": b64url(authData),
			"signature":         b64url(sig),
		},
	}
	b, _ := json.Marshal(resp)
	return string(b)
}

func post(strat *Strategy, body string) *passport.Context {
	c := &passport.Context{}
	req, _ := http.NewRequest("POST", "/login", strings.NewReader(body))
	strat.Authenticate(c, req)
	return c
}

// ---- Name -------------------------------------------------------------------

func TestName(t *testing.T) {
	if New(Config{}, nil, nil).Name() != "webauthn" {
		t.Fatal("name")
	}
}

// ---- CBOR decoder edge cases ------------------------------------------------

func TestCBORDecodePrimitives(t *testing.T) {
	if v, _, _ := cborDecode(cint(-5)); v != int64(-5) {
		t.Fatalf("neg int: %v", v)
	}
	if v, _, _ := cborDecode(ctext("hi")); v != "hi" {
		t.Fatalf("text: %v", v)
	}
	// array [1, 2]
	arrData := append(cuint(4, 2), append(cint(1), cint(2)...)...)
	v, _, err := cborDecode(arrData)
	if err != nil {
		t.Fatal(err)
	}
	arr, ok := v.([]any)
	if !ok || len(arr) != 2 || arr[0] != int64(1) || arr[1] != int64(2) {
		t.Fatalf("array: %v", v)
	}
	// simple values
	if v, _, _ := cborDecode([]byte{0xf4}); v != false {
		t.Fatalf("false: %v", v)
	}
	if v, _, _ := cborDecode([]byte{0xf5}); v != true {
		t.Fatalf("true: %v", v)
	}
	if v, _, _ := cborDecode([]byte{0xf6}); v != nil {
		t.Fatalf("null: %v", v)
	}
	if v, _, _ := cborDecode([]byte{0xf7}); v != nil {
		t.Fatalf("undef: %v", v)
	}
	// default simple (minor < 20)
	if v, _, _ := cborDecode([]byte{0xe0}); v != int64(0) {
		t.Fatalf("simple default: %v", v)
	}
	// float32 (0xfa) and float64 (0xfb)
	f32 := []byte{0xfa, 0, 0, 0, 0}
	binary.BigEndian.PutUint32(f32[1:], math.Float32bits(1.5))
	if v, _, _ := cborDecode(f32); v != float64(1.5) {
		t.Fatalf("float32: %v", v)
	}
	f64 := []byte{0xfb, 0, 0, 0, 0, 0, 0, 0, 0}
	binary.BigEndian.PutUint64(f64[1:], math.Float64bits(2.5))
	if v, _, _ := cborDecode(f64); v != 2.5 {
		t.Fatalf("float64: %v", v)
	}
	// tag (major 6): tag 1 wrapping int 5
	if v, _, _ := cborDecode([]byte{0xc1, 0x05}); v != int64(5) {
		t.Fatalf("tag: %v", v)
	}
}

func TestCBORDecodeErrors(t *testing.T) {
	if _, _, err := cborDecode(nil); err == nil {
		t.Fatal("empty should error")
	}
	// byte string claims 2 bytes but only 1 present
	if _, _, err := cborDecode([]byte{0x42, 0x01}); err == nil {
		t.Fatal("truncated byte string should error")
	}
	// text string truncated
	if _, _, err := cborDecode([]byte{0x62, 0x41}); err == nil {
		t.Fatal("truncated text should error")
	}
	// array element decode error
	if _, _, err := cborDecode([]byte{0x81, 0x42, 0x01}); err == nil {
		t.Fatal("array with bad element should error")
	}
	// map with truncated value
	if _, _, err := cborDecode([]byte{0xa1, 0x01, 0x42, 0x00}); err == nil {
		t.Fatal("map with bad value should error")
	}
	// tag with bad content
	if _, _, err := cborDecode([]byte{0xc1, 0x42, 0x00}); err == nil {
		t.Fatal("tag with bad content should error")
	}
}

func TestCBORArgWidths(t *testing.T) {
	if v, _, _ := cborDecode(cuint(0, 200)); v != int64(200) {
		t.Fatalf("1-byte arg: %v", v)
	}
	if v, _, _ := cborDecode(cuint(0, 300)); v != int64(300) {
		t.Fatalf("2-byte arg: %v", v)
	}
	if v, _, _ := cborDecode(cuint(0, 70000)); v != int64(70000) {
		t.Fatalf("4-byte arg: %v", v)
	}
	if v, _, _ := cborDecode(cuint(0, 5_000_000_000)); v != int64(5_000_000_000) {
		t.Fatalf("8-byte arg: %v", v)
	}
	// truncated arguments
	for _, b := range [][]byte{{0x18}, {0x19, 0x01}, {0x1a, 0x01}, {0x1b, 0x01}} {
		if _, _, err := cborDecode(b); err == nil {
			t.Fatalf("truncated arg %x should error", b)
		}
	}
	// invalid minor (28)
	if _, _, err := cborDecode([]byte{0x1c}); err == nil {
		t.Fatal("minor 28 should error")
	}
}

// ---- COSE key parsing -------------------------------------------------------

func TestParseCOSEKeyErrors(t *testing.T) {
	// not CBOR at all
	if _, _, _, err := parseCOSEKey(nil); err == nil {
		t.Fatal("nil should error")
	}
	// not a map (an int)
	if _, _, _, err := parseCOSEKey(cint(5)); err != ErrUnsupportedKey {
		t.Fatalf("non-map: %v", err)
	}
	// EC2 missing x/y
	badEC := cmap(cpair(cint(1), cint(2)), cpair(cint(-1), cint(1)))
	if _, _, _, err := parseCOSEKey(badEC); err != ErrUnsupportedKey {
		t.Fatalf("EC missing coords: %v", err)
	}
	// EC2 wrong curve
	wrongCrv := cmap(
		cpair(cint(1), cint(2)),
		cpair(cint(-1), cint(2)), // not P-256
		cpair(cint(-2), cbytes(make([]byte, 32))),
		cpair(cint(-3), cbytes(make([]byte, 32))),
	)
	if _, _, _, err := parseCOSEKey(wrongCrv); err != ErrUnsupportedKey {
		t.Fatalf("EC wrong curve: %v", err)
	}
	// RSA missing n/e
	badRSA := cmap(cpair(cint(1), cint(3)), cpair(cint(3), cint(-257)))
	if _, _, _, err := parseCOSEKey(badRSA); err != ErrUnsupportedKey {
		t.Fatalf("RSA missing params: %v", err)
	}
	// unsupported kty
	badKty := cmap(cpair(cint(1), cint(9)))
	if _, _, _, err := parseCOSEKey(badKty); err != ErrUnsupportedKey {
		t.Fatalf("bad kty: %v", err)
	}
}

func TestParseCOSEKeyRSA(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	pub, _, alg, err := parseCOSEKey(coseKeyRSA(&key.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	if alg != -257 {
		t.Fatalf("alg=%d", alg)
	}
	rp, ok := pub.(*rsa.PublicKey)
	if !ok || rp.N.Cmp(key.PublicKey.N) != 0 || rp.E != key.PublicKey.E {
		t.Fatal("RSA key mismatch")
	}
}

// ---- RSA registration + authentication end to end --------------------------

func TestRSARegistrationAndAuthentication(t *testing.T) {
	cfg := Config{RPID: testRPID, RPOrigin: testOrigin, RPName: "Example"}
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	credID := []byte("rsa-cred")
	cose := coseKeyRSA(&priv.PublicKey)

	regChallenge, _, _ := cfg.BeginRegistration("u", "n", "d")
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
	if _, ok := cred.PublicKey.(*rsa.PublicKey); !ok {
		t.Fatalf("key type %T", cred.PublicKey)
	}

	store := &memStore{user: "rsa@example.com", cred: cred}
	authChallenge, _, _ := cfg.BeginAuthentication([][]byte{credID})
	strat := New(cfg, store, func(r *http.Request) []byte { return authChallenge })
	assertion := signAssertionRSA(t, priv, testRPID, testOrigin, authChallenge, credID, 1)
	c := post(strat, assertion)
	if c.Result() != passport.ResultSuccess {
		t.Fatalf("want success, got %v (%v)", c.Result(), c.Err())
	}
}

// ---- Authenticate failure/error paths ---------------------------------------

func newStrat(t *testing.T, cred *Credential, challenge []byte) *Strategy {
	cfg := Config{RPID: testRPID, RPOrigin: testOrigin}
	store := &memStore{user: "x", cred: cred}
	return New(cfg, store, func(r *http.Request) []byte { return challenge })
}

func TestAuthenticateBodyReadError(t *testing.T) {
	cfg := Config{RPID: testRPID, RPOrigin: testOrigin}
	strat := New(cfg, &memStore{cred: &Credential{ID: []byte("c")}}, func(r *http.Request) []byte { return nil })
	c := &passport.Context{}
	req, _ := http.NewRequest("POST", "/", errReader{})
	strat.Authenticate(c, req)
	if c.Result() != passport.ResultError {
		t.Fatalf("want error, got %v", c.Result())
	}
}

func TestAuthenticateInvalidJSON(t *testing.T) {
	strat := newStrat(t, &Credential{ID: []byte("c")}, nil)
	c := post(strat, "{not json")
	if c.Result() != passport.ResultFail {
		t.Fatalf("want fail, got %v", c.Result())
	}
}

func TestAuthenticateBadCredID(t *testing.T) {
	strat := newStrat(t, &Credential{ID: []byte("c")}, nil)
	// Empty id/rawId → b64decode("") fails.
	c := post(strat, `{"id":"","rawId":"","type":"public-key","response":{}}`)
	if c.Result() != passport.ResultFail || c.Challenge() != "invalid credential id" {
		t.Fatalf("result=%v challenge=%q", c.Result(), c.Challenge())
	}
}

func TestAuthenticateMalformedAssertion(t *testing.T) {
	strat := newStrat(t, &Credential{ID: []byte("c")}, nil)
	// Valid cred id but clientDataJSON is not valid base64.
	body := `{"id":"YQ","rawId":"YQ","type":"public-key","response":{"clientDataJSON":"@@@","authenticatorData":"YQ","signature":"YQ"}}`
	c := post(strat, body)
	if c.Result() != passport.ResultFail || c.Challenge() != "malformed assertion" {
		t.Fatalf("result=%v challenge=%q", c.Result(), c.Challenge())
	}
}

func TestAuthenticateStoreError(t *testing.T) {
	cfg := Config{RPID: testRPID, RPOrigin: testOrigin}
	strat := New(cfg, errStore{}, func(r *http.Request) []byte { return nil })
	priv, _ := generateES256(t)
	challenge, _ := NewChallenge()
	assertion := signAssertion(t, priv, testRPID, testOrigin, challenge, []byte("c"), 1)
	c := post(strat, assertion)
	if c.Result() != passport.ResultError {
		t.Fatalf("want error, got %v", c.Result())
	}
}

func TestAuthenticateUnknownCredential(t *testing.T) {
	priv, _ := generateES256(t)
	credID := []byte("known")
	cred := &Credential{ID: credID, PublicKey: pubOf(priv)}
	challenge, _ := NewChallenge()
	strat := newStrat(t, cred, challenge)
	// Sign with a different credential id the store won't find.
	assertion := signAssertion(t, priv, testRPID, testOrigin, challenge, []byte("other"), 1)
	c := post(strat, assertion)
	if c.Result() != passport.ResultFail || c.Challenge() != "unknown credential" {
		t.Fatalf("result=%v challenge=%q", c.Result(), c.Challenge())
	}
}

func TestAuthenticateChallengeMismatch(t *testing.T) {
	priv, _ := generateES256(t)
	credID := []byte("c")
	cred := &Credential{ID: credID, PublicKey: pubOf(priv)}
	strat := newStrat(t, cred, []byte("expected-challenge-value"))
	// Assertion signed with a different challenge.
	assertion := signAssertion(t, priv, testRPID, testOrigin, []byte("actual-challenge"), credID, 1)
	c := post(strat, assertion)
	if c.Result() != passport.ResultFail || c.Challenge() != "challenge/origin mismatch" {
		t.Fatalf("result=%v challenge=%q", c.Result(), c.Challenge())
	}
}

func TestAuthenticateBadAuthData(t *testing.T) {
	priv, _ := generateES256(t)
	credID := []byte("c")
	cred := &Credential{ID: credID, PublicKey: pubOf(priv)}
	challenge, _ := NewChallenge()
	strat := newStrat(t, cred, challenge)
	cd := clientDataJSON("webauthn.get", testOrigin, challenge)
	// authenticatorData too short (<37 bytes).
	body := buildResp(credID, cd, []byte("short"), []byte("sig"))
	c := post(strat, body)
	if c.Result() != passport.ResultFail || c.Challenge() != "bad authenticator data" {
		t.Fatalf("result=%v challenge=%q", c.Result(), c.Challenge())
	}
}

func TestAuthenticateRPIDMismatch(t *testing.T) {
	priv, _ := generateES256(t)
	credID := []byte("c")
	cred := &Credential{ID: credID, PublicKey: pubOf(priv)}
	challenge, _ := NewChallenge()
	strat := newStrat(t, cred, challenge)
	cd := clientDataJSON("webauthn.get", testOrigin, challenge)
	authData := makeAuthData("wrong.example", flagUserPresent, 1, nil, nil)
	body := buildResp(credID, cd, authData, []byte("sig"))
	c := post(strat, body)
	if c.Result() != passport.ResultFail || c.Challenge() != "rp id mismatch" {
		t.Fatalf("result=%v challenge=%q", c.Result(), c.Challenge())
	}
}

func TestAuthenticateUserNotPresent(t *testing.T) {
	priv, _ := generateES256(t)
	credID := []byte("c")
	cred := &Credential{ID: credID, PublicKey: pubOf(priv)}
	challenge, _ := NewChallenge()
	strat := newStrat(t, cred, challenge)
	cd := clientDataJSON("webauthn.get", testOrigin, challenge)
	authData := makeAuthData(testRPID, 0, 1, nil, nil) // no user-present flag
	body := buildResp(credID, cd, authData, []byte("sig"))
	c := post(strat, body)
	if c.Result() != passport.ResultFail || c.Challenge() != "user not present" {
		t.Fatalf("result=%v challenge=%q", c.Result(), c.Challenge())
	}
}

func TestAuthenticateClonedAuthenticator(t *testing.T) {
	priv, _ := generateES256(t)
	credID := []byte("c")
	cred := &Credential{ID: credID, PublicKey: pubOf(priv), SignCount: 5}
	challenge, _ := NewChallenge()
	strat := newStrat(t, cred, challenge)
	// Sign a valid assertion but with a lower counter than stored.
	assertion := signAssertion(t, priv, testRPID, testOrigin, challenge, credID, 3)
	c := post(strat, assertion)
	if c.Result() != passport.ResultFail || c.Challenge() != "possible cloned authenticator" {
		t.Fatalf("result=%v challenge=%q", c.Result(), c.Challenge())
	}
}

func TestAuthenticateUpdatesSignCount(t *testing.T) {
	priv, _ := generateES256(t)
	credID := []byte("c")
	cred := &Credential{ID: credID, PublicKey: pubOf(priv), SignCount: 0}
	challenge, _ := NewChallenge()
	cfg := Config{RPID: testRPID, RPOrigin: testOrigin}
	store := &updaterStore{user: "u", cred: cred}
	strat := New(cfg, store, func(r *http.Request) []byte { return challenge })
	assertion := signAssertion(t, priv, testRPID, testOrigin, challenge, credID, 7)
	c := post(strat, assertion)
	if c.Result() != passport.ResultSuccess {
		t.Fatalf("want success, got %v (%v)", c.Result(), c.Err())
	}
	if !store.called || store.newCnt != 7 {
		t.Fatalf("updater called=%v cnt=%d", store.called, store.newCnt)
	}
}

// ---- verifyClientData / verifyAssertionSignature direct ---------------------

func TestVerifyClientDataErrors(t *testing.T) {
	cfg := Config{RPOrigin: testOrigin}
	// invalid JSON
	if err := cfg.verifyClientData([]byte("{bad"), "webauthn.get", nil); err != ErrVerification {
		t.Fatalf("json: %v", err)
	}
	// wrong type
	cd := clientDataJSON("webauthn.create", testOrigin, []byte("chal"))
	if err := cfg.verifyClientData(cd, "webauthn.get", []byte("chal")); err != ErrVerification {
		t.Fatalf("type: %v", err)
	}
	// wrong challenge
	cd = clientDataJSON("webauthn.get", testOrigin, []byte("chal"))
	if err := cfg.verifyClientData(cd, "webauthn.get", []byte("different")); err != ErrVerification {
		t.Fatalf("challenge: %v", err)
	}
}

func TestVerifyAssertionSignatureUnsupported(t *testing.T) {
	cred := &Credential{PublicKey: "not-a-key"}
	if err := verifyAssertionSignature(cred, []byte("a"), []byte("b"), []byte("c")); err != ErrUnsupportedKey {
		t.Fatalf("want ErrUnsupportedKey, got %v", err)
	}
}

// ---- FinishRegistration failure paths ---------------------------------------

func TestFinishRegistrationErrors(t *testing.T) {
	cfg := Config{RPID: testRPID, RPOrigin: testOrigin}
	challenge := []byte("chal")
	goodCD := clientDataJSON("webauthn.create", testOrigin, challenge)

	// clientData verification failure (wrong challenge).
	if _, err := cfg.FinishRegistration(cmap(), goodCD, []byte("other")); err != ErrVerification {
		t.Fatalf("clientData: %v", err)
	}
	// attestation not CBOR.
	if _, err := cfg.FinishRegistration(nil, goodCD, challenge); err != ErrBadAttestation {
		t.Fatalf("bad cbor: %v", err)
	}
	// attestation not a map.
	if _, err := cfg.FinishRegistration(cint(5), goodCD, challenge); err != ErrBadAttestation {
		t.Fatalf("non-map: %v", err)
	}
	// map without authData.
	noAuth := cmap(cpair(ctext("fmt"), ctext("none")))
	if _, err := cfg.FinishRegistration(noAuth, goodCD, challenge); err != ErrBadAttestation {
		t.Fatalf("missing authData: %v", err)
	}
	// authData too short → parseAuthData error.
	shortAD := cmap(cpair(ctext("authData"), cbytes([]byte("short"))))
	if _, err := cfg.FinishRegistration(shortAD, goodCD, challenge); err != ErrBadAttestation {
		t.Fatalf("short authData: %v", err)
	}
	// authData without attested-credential flag.
	noCred := makeAuthData(testRPID, flagUserPresent, 0, nil, nil)
	noCredObj := cmap(cpair(ctext("authData"), cbytes(noCred)))
	if _, err := cfg.FinishRegistration(noCredObj, goodCD, challenge); err != ErrBadAttestation {
		t.Fatalf("no attested cred: %v", err)
	}
}

func TestFinishRegistrationRPMismatch(t *testing.T) {
	cfg := Config{RPID: testRPID, RPOrigin: testOrigin}
	challenge := []byte("chal")
	goodCD := clientDataJSON("webauthn.create", testOrigin, challenge)
	priv, _ := generateES256(t)
	credID := []byte("c")
	cose := coseKeyOf(priv)
	// authData built for a different RP ID → rpIDHash mismatch.
	wrongRP := makeAuthData("other.example", flagUserPresent|flagAttestedCred, 0, credID, cose)
	obj := cmap(cpair(ctext("authData"), cbytes(wrongRP)))
	if _, err := cfg.FinishRegistration(obj, goodCD, challenge); err != ErrVerification {
		t.Fatalf("rp mismatch: %v", err)
	}
	// user-present flag missing → verification failure.
	noUP := makeAuthData(testRPID, flagAttestedCred, 0, credID, cose)
	obj2 := cmap(cpair(ctext("authData"), cbytes(noUP)))
	if _, err := cfg.FinishRegistration(obj2, goodCD, challenge); err != ErrVerification {
		t.Fatalf("no user present: %v", err)
	}
}

// ---- small helpers ----------------------------------------------------------

func TestAsIntAndBytesEqual(t *testing.T) {
	if v, ok := asInt(int(9)); !ok || v != 9 {
		t.Fatalf("asInt int: %v %v", v, ok)
	}
	if v, ok := asInt(int64(4)); !ok || v != 4 {
		t.Fatalf("asInt int64: %v %v", v, ok)
	}
	if _, ok := asInt("x"); ok {
		t.Fatal("asInt string should be false")
	}
	if bytesEqual([]byte{1}, []byte{2}) {
		t.Fatal("bytesEqual differing bytes")
	}
	if bytesEqual([]byte{1}, []byte{1, 2}) {
		t.Fatal("bytesEqual differing lengths")
	}
	if !bytesEqual([]byte{1, 2}, []byte{1, 2}) {
		t.Fatal("bytesEqual equal")
	}
}
