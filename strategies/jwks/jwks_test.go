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
	"math/big"
	"testing"
	"time"
)

const cryptoSHA256 = crypto.SHA256

// ecdsaSig serializes an ECDSA signature as fixed-width r||s (JWS format).
func ecdsaSig(r, s *big.Int, size int) []byte {
	out := make([]byte, 2*size)
	r.FillBytes(out[:size])
	s.FillBytes(out[size:])
	return out
}

// hmacSHA256 computes an HMAC-SHA256 tag.
func hmacSHA256(secret []byte, msg string) []byte {
	m := hmac.New(sha256.New, secret)
	m.Write([]byte(msg))
	return m.Sum(nil)
}

// sign builds a compact JWS from a header and claims, signing the signing input
// with the given function.
func sign(t *testing.T, hdr header, claims Claims, signer func(signingInput string) []byte) string {
	t.Helper()
	hb, _ := json.Marshal(hdr)
	cb, _ := json.Marshal(claims)
	si := b64.EncodeToString(hb) + "." + b64.EncodeToString(cb)
	sig := signer(si)
	return si + "." + b64.EncodeToString(sig)
}

func TestVerifyRS256(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	claims := Claims{"sub": "abc", "iss": "https://issuer", "exp": float64(time.Now().Add(time.Hour).Unix())}
	token := sign(t, header{Alg: "RS256", Kid: "k1"}, claims, func(si string) []byte {
		h := sha256.Sum256([]byte(si))
		sig, _ := rsa.SignPKCS1v15(rand.Reader, key, cryptoSHA256, h[:])
		return sig
	})

	got, err := Verify(token, func(kid, alg string) (any, error) {
		if kid != "k1" || alg != "RS256" {
			t.Fatalf("resolver got kid=%q alg=%q", kid, alg)
		}
		return &key.PublicKey, nil
	})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if got.Subject() != "abc" || got.Issuer() != "https://issuer" {
		t.Fatalf("claims = %+v", got)
	}
}

func TestVerifyES256(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	token := sign(t, header{Alg: "ES256", Kid: "e1"}, Claims{"sub": "ec-user"}, func(si string) []byte {
		h := sha256.Sum256([]byte(si))
		r, s, _ := ecdsa.Sign(rand.Reader, key, h[:])
		return ecdsaSig(r, s, 32)
	})
	got, err := Verify(token, func(kid, alg string) (any, error) {
		return &key.PublicKey, nil
	})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if got.Subject() != "ec-user" {
		t.Fatalf("sub = %q", got.Subject())
	}
}

func TestVerifyES512(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	token := sign(t, header{Alg: "ES512", Kid: "e5"}, Claims{"sub": "big"}, func(si string) []byte {
		h := sha512.Sum512([]byte(si))
		r, s, _ := ecdsa.Sign(rand.Reader, key, h[:])
		return ecdsaSig(r, s, 66)
	})
	if _, err := Verify(token, func(kid, alg string) (any, error) { return &key.PublicKey, nil }); err != nil {
		t.Fatalf("Verify: %v", err)
	}
}

func TestVerifyHS256(t *testing.T) {
	secret := []byte("topsecret")
	token := sign(t, header{Alg: "HS256"}, Claims{"sub": "h"}, func(si string) []byte {
		return hmacSHA256(secret, si)
	})
	if _, err := Verify(token, func(kid, alg string) (any, error) { return secret, nil }); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	// Wrong secret must fail.
	if _, err := Verify(token, func(kid, alg string) (any, error) { return []byte("nope"), nil }); err != ErrSignature {
		t.Fatalf("expected ErrSignature, got %v", err)
	}
}

func TestVerifyExpired(t *testing.T) {
	secret := []byte("s")
	token := sign(t, header{Alg: "HS256"}, Claims{"exp": float64(time.Now().Add(-time.Hour).Unix())}, func(si string) []byte {
		return hmacSHA256(secret, si)
	})
	if _, err := Verify(token, func(kid, alg string) (any, error) { return secret, nil }); err == nil {
		t.Fatal("expected expired error")
	}
}

func TestJWKSRoundTrip(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	// Build a JWKS document from the public key.
	set := Set{Keys: []JWK{{
		Kty: "RSA",
		Kid: "kid-1",
		Alg: "RS256",
		Use: "sig",
		N:   b64.EncodeToString(key.PublicKey.N.Bytes()),
		E:   b64.EncodeToString(big.NewInt(int64(key.PublicKey.E)).Bytes()),
	}}}
	data, _ := json.Marshal(set)

	parsed, err := ParseSet(data)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := parsed.Key("kid-1")
	if err != nil {
		t.Fatal(err)
	}
	rp, ok := pub.(*rsa.PublicKey)
	if !ok {
		t.Fatalf("key type %T", pub)
	}
	if rp.N.Cmp(key.PublicKey.N) != 0 || rp.E != key.PublicKey.E {
		t.Fatal("recovered RSA key mismatch")
	}

	// End-to-end: sign, resolve via the set, verify.
	token := sign(t, header{Alg: "RS256", Kid: "kid-1"}, Claims{"sub": "e2e"}, func(si string) []byte {
		h := sha256.Sum256([]byte(si))
		sig, _ := rsa.SignPKCS1v15(rand.Reader, key, cryptoSHA256, h[:])
		return sig
	})
	got, err := Verify(token, func(kid, alg string) (any, error) { return parsed.Key(kid) })
	if err != nil {
		t.Fatalf("Verify via JWKS: %v", err)
	}
	if got.Subject() != "e2e" {
		t.Fatalf("sub = %q", got.Subject())
	}
}

func TestJWKSECRoundTrip(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	set := Set{Keys: []JWK{{
		Kty: "EC",
		Kid: "ec-1",
		Crv: "P-256",
		X:   b64.EncodeToString(key.PublicKey.X.Bytes()),
		Y:   b64.EncodeToString(key.PublicKey.Y.Bytes()),
	}}}
	data, _ := json.Marshal(set)
	parsed, err := ParseSet(data)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := parsed.Key("ec-1")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := pub.(*ecdsa.PublicKey); !ok {
		t.Fatalf("key type %T", pub)
	}
}
