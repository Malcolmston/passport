package jwks

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/json"
	"hash"
	"math/big"
	"testing"
	"time"
)

// signRSAlg signs with an arbitrary RSA algorithm (RS*/PS*).
func signRSAlg(t *testing.T, key *rsa.PrivateKey, alg string, claims Claims) string {
	t.Helper()
	var h crypto.Hash
	switch alg[len(alg)-3:] {
	case "256":
		h = crypto.SHA256
	case "384":
		h = crypto.SHA384
	case "512":
		h = crypto.SHA512
	}
	return sign(t, header{Alg: alg}, claims, func(si string) []byte {
		hh := h.New()
		hh.Write([]byte(si))
		digest := hh.Sum(nil)
		if alg[:2] == "PS" {
			sig, err := rsa.SignPSS(rand.Reader, key, h, digest, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
			if err != nil {
				t.Fatal(err)
			}
			return sig
		}
		sig, err := rsa.SignPKCS1v15(rand.Reader, key, h, digest)
		if err != nil {
			t.Fatal(err)
		}
		return sig
	})
}

func TestVerifyRSAlgorithms(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	for _, alg := range []string{"RS384", "RS512", "PS256", "PS384", "PS512"} {
		tok := signRSAlg(t, key, alg, Claims{"sub": "u"})
		if _, err := Verify(tok, func(kid, a string) (any, error) { return &key.PublicKey, nil }); err != nil {
			t.Fatalf("%s: %v", alg, err)
		}
	}
}

func TestVerifyESAlgorithms(t *testing.T) {
	cases := []struct {
		alg   string
		curve elliptic.Curve
		newH  func() hash.Hash
		size  int
	}{
		{"ES384", elliptic.P384(), sha512.New384, 48},
	}
	for _, tc := range cases {
		key, err := ecdsa.GenerateKey(tc.curve, rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		tok := sign(t, header{Alg: tc.alg}, Claims{"sub": "e"}, func(si string) []byte {
			hh := tc.newH()
			hh.Write([]byte(si))
			r, s, _ := ecdsa.Sign(rand.Reader, key, hh.Sum(nil))
			return ecdsaSig(r, s, tc.size)
		})
		if _, err := Verify(tok, func(kid, a string) (any, error) { return &key.PublicKey, nil }); err != nil {
			t.Fatalf("%s: %v", tc.alg, err)
		}
	}
}

func TestVerifyHSAlgorithms(t *testing.T) {
	secret := []byte("shared-secret")
	for _, tc := range []struct {
		alg  string
		newH func() hash.Hash
	}{
		{"HS384", sha512.New384},
		{"HS512", sha512.New},
	} {
		tok := sign(t, header{Alg: tc.alg}, Claims{"sub": "h"}, func(si string) []byte {
			m := hmac.New(tc.newH, secret)
			m.Write([]byte(si))
			return m.Sum(nil)
		})
		if _, err := Verify(tok, func(kid, a string) (any, error) { return secret, nil }); err != nil {
			t.Fatalf("%s: %v", tc.alg, err)
		}
	}
}

func TestVerifySignatureKeyTypeMismatch(t *testing.T) {
	// Each branch requires a specific key type; the wrong type must yield ErrKey.
	if err := verifySignature("HS256", "not-bytes", "x", nil); err != ErrKey {
		t.Fatalf("HS wrong key: %v", err)
	}
	if err := verifySignature("RS256", "not-rsa", "x", nil); err != ErrKey {
		t.Fatalf("RS wrong key: %v", err)
	}
	if err := verifySignature("PS256", "not-rsa", "x", nil); err != ErrKey {
		t.Fatalf("PS wrong key: %v", err)
	}
	if err := verifySignature("ES256", "not-ecdsa", "x", nil); err != ErrKey {
		t.Fatalf("ES wrong key: %v", err)
	}
	if err := verifySignature("XX256", nil, "x", nil); err != ErrAlgorithm {
		t.Fatalf("unknown alg family: %v", err)
	}
}

func TestVerifySignatureESBadLength(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err := verifySignature("ES256", &key.PublicKey, "x", []byte{1, 2, 3}); err != ErrSignature {
		t.Fatalf("odd-length sig: %v", err)
	}
	if err := verifySignature("ES256", &key.PublicKey, "x", nil); err != ErrSignature {
		t.Fatalf("empty sig: %v", err)
	}
}

func TestHasherForUnknown(t *testing.T) {
	if _, _, err := hasherFor("RS999"); err != ErrAlgorithm {
		t.Fatalf("want ErrAlgorithm, got %v", err)
	}
}

func TestNumeric(t *testing.T) {
	if v, ok := numeric(int64(7)); !ok || v != 7 {
		t.Fatalf("int64: %v %v", v, ok)
	}
	if v, ok := numeric(int(3)); !ok || v != 3 {
		t.Fatalf("int: %v %v", v, ok)
	}
	if v, ok := numeric(2.5); !ok || v != 2.5 {
		t.Fatalf("float64: %v %v", v, ok)
	}
	if _, ok := numeric("nope"); ok {
		t.Fatal("string should not be numeric")
	}
}

func TestCheckTimes(t *testing.T) {
	fixed := time.Unix(1_000_000, 0)
	old := timeNow
	timeNow = func() time.Time { return fixed }
	defer func() { timeNow = old }()

	// nbf in the future beyond leeway → not yet valid.
	if err := checkTimes(Claims{"nbf": float64(fixed.Unix() + 2*leewaySeconds)}); err == nil {
		t.Fatal("expected not-yet-valid error")
	}
	// nbf within leeway → ok.
	if err := checkTimes(Claims{"nbf": float64(fixed.Unix() + leewaySeconds/2)}); err != nil {
		t.Fatalf("nbf within leeway: %v", err)
	}
	// exp in the past beyond leeway → expired.
	if err := checkTimes(Claims{"exp": float64(fixed.Unix() - 2*leewaySeconds)}); err == nil {
		t.Fatal("expected expired error")
	}
	// exp within leeway → ok.
	if err := checkTimes(Claims{"exp": float64(fixed.Unix() - leewaySeconds/2)}); err != nil {
		t.Fatalf("exp within leeway: %v", err)
	}
	// no time claims → ok.
	if err := checkTimes(Claims{}); err != nil {
		t.Fatalf("no claims: %v", err)
	}
}

func TestClaimsAudience(t *testing.T) {
	if got := (Claims{"aud": "single"}).Audience(); len(got) != 1 || got[0] != "single" {
		t.Fatalf("string aud: %v", got)
	}
	got := (Claims{"aud": []any{"a", "b", 42}}).Audience()
	if len(got) != 2 || got[0] != "a" || got[1] != "b" {
		t.Fatalf("[]any aud: %v", got)
	}
	if got := (Claims{}).Audience(); got != nil {
		t.Fatalf("missing aud: %v", got)
	}
}

func TestJWKPublicKeyErrors(t *testing.T) {
	if _, err := (JWK{Kty: "RSA", N: "!!!bad", E: "AQAB"}).PublicKey(); err != ErrMalformed {
		t.Fatalf("bad N: %v", err)
	}
	if _, err := (JWK{Kty: "RSA", N: "AQAB", E: "!!!bad"}).PublicKey(); err != ErrMalformed {
		t.Fatalf("bad E: %v", err)
	}
	if _, err := (JWK{Kty: "EC", Crv: "P-256", X: "!!!bad", Y: "AQAB"}).PublicKey(); err != ErrMalformed {
		t.Fatalf("bad X: %v", err)
	}
	if _, err := (JWK{Kty: "EC", Crv: "P-256", X: "AQAB", Y: "!!!bad"}).PublicKey(); err != ErrMalformed {
		t.Fatalf("bad Y: %v", err)
	}
	if _, err := (JWK{Kty: "EC", Crv: "bogus", X: "AQAB", Y: "AQAB"}).PublicKey(); err != ErrAlgorithm {
		t.Fatalf("bad crv: %v", err)
	}
	if _, err := (JWK{Kty: "oct"}).PublicKey(); err != ErrAlgorithm {
		t.Fatalf("unsupported kty: %v", err)
	}
}

func TestCurveFor(t *testing.T) {
	for _, crv := range []string{"P-384", "P-521"} {
		var curve elliptic.Curve
		if crv == "P-384" {
			curve = elliptic.P384()
		} else {
			curve = elliptic.P521()
		}
		key, _ := ecdsa.GenerateKey(curve, rand.Reader)
		jwk := JWK{Kty: "EC", Crv: crv, X: b64.EncodeToString(key.PublicKey.X.Bytes()), Y: b64.EncodeToString(key.PublicKey.Y.Bytes())}
		pub, err := jwk.PublicKey()
		if err != nil {
			t.Fatalf("%s: %v", crv, err)
		}
		if _, ok := pub.(*ecdsa.PublicKey); !ok {
			t.Fatalf("%s: type %T", crv, pub)
		}
	}
}

func TestSetKey(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	jwk := JWK{Kty: "RSA", Kid: "only", N: b64.EncodeToString(key.PublicKey.N.Bytes()), E: b64.EncodeToString(big.NewInt(int64(key.PublicKey.E)).Bytes())}
	set := &Set{Keys: []JWK{jwk}}
	// Empty kid with a single key → returns that key.
	if _, err := set.Key(""); err != nil {
		t.Fatalf("empty kid single key: %v", err)
	}
	// Unknown kid → ErrKey.
	if _, err := set.Key("nope"); err != ErrKey {
		t.Fatalf("unknown kid: %v", err)
	}
}

func TestParseSetBadJSON(t *testing.T) {
	if _, err := ParseSet([]byte("{not json")); err == nil {
		t.Fatal("expected parse error")
	}
}

func TestVerifyMalformed(t *testing.T) {
	// Wrong number of segments.
	if _, err := Verify("only.two", nil); err != ErrMalformed {
		t.Fatalf("two parts: %v", err)
	}
	// Bad header base64.
	if _, err := Verify("!!!.x.y", nil); err != ErrMalformed {
		t.Fatalf("bad header b64: %v", err)
	}
	// Header not JSON.
	badHdr := b64.EncodeToString([]byte("not json")) + ".x.y"
	if _, err := Verify(badHdr, func(kid, alg string) (any, error) { return nil, nil }); err != ErrMalformed {
		t.Fatalf("header json: %v", err)
	}
	// Resolver error propagates.
	hb, _ := json.Marshal(header{Alg: "RS256"})
	tok := b64.EncodeToString(hb) + ".e30.AAAA"
	if _, err := Verify(tok, func(kid, alg string) (any, error) { return nil, ErrKey }); err != ErrKey {
		t.Fatalf("resolver error: %v", err)
	}
	// Bad signature base64.
	tok2 := b64.EncodeToString(hb) + ".e30.!!!"
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	if _, err := Verify(tok2, func(kid, alg string) (any, error) { return &key.PublicKey, nil }); err != ErrMalformed {
		t.Fatalf("bad sig b64: %v", err)
	}
}

func TestVerifyBadPayload(t *testing.T) {
	// A valid HS256 signature over a payload that is valid base64 but not JSON.
	secret := []byte("s")
	hb, _ := json.Marshal(header{Alg: "HS256"})
	payload := b64.EncodeToString([]byte("not json"))
	si := b64.EncodeToString(hb) + "." + payload
	m := hmac.New(sha256.New, secret)
	m.Write([]byte(si))
	tok := si + "." + b64.EncodeToString(m.Sum(nil))
	if _, err := Verify(tok, func(kid, alg string) (any, error) { return secret, nil }); err != ErrMalformed {
		t.Fatalf("payload json: %v", err)
	}
}
