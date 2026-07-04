// Package jwks verifies JSON Web Tokens signed with asymmetric keys (RS256/384/
// 512, PS256/384/512, ES256/384/512) whose public keys are published as a JWKS
// (JSON Web Key Set), as used by OpenID Connect providers such as Google, Auth0,
// Okta, and Azure AD. It also supports HS256/384/512 with a shared secret. It
// uses only the standard library.
package jwks

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
	"hash"
	"math/big"
	"strings"
	"time"
)

// Claims is a decoded JWT payload.
type Claims map[string]any

// Subject returns the "sub" claim.
func (c Claims) Subject() string { s, _ := c["sub"].(string); return s }

// Issuer returns the "iss" claim.
func (c Claims) Issuer() string { s, _ := c["iss"].(string); return s }

// Audience returns the "aud" claim as a slice (JWT allows string or []string).
func (c Claims) Audience() []string {
	switch v := c["aud"].(type) {
	case string:
		return []string{v}
	case []any:
		out := make([]string, 0, len(v))
		for _, a := range v {
			if s, ok := a.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

// Common errors.
var (
	ErrMalformed = errors.New("jwks: malformed token")
	ErrSignature = errors.New("jwks: signature verification failed")
	ErrAlgorithm = errors.New("jwks: unsupported or unexpected algorithm")
	ErrKey       = errors.New("jwks: no matching key")
)

// header is the decoded JWT header.
type header struct {
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	Typ string `json:"typ"`
}

// KeyResolver returns the verification key for a token's kid and algorithm. The
// returned key is *rsa.PublicKey, *ecdsa.PublicKey, or []byte (HMAC secret).
type KeyResolver func(kid, alg string) (any, error)

// Verify parses and verifies a JWT using resolve to obtain the key, then checks
// the exp/nbf time claims. It returns the claims on success.
func Verify(token string, resolve KeyResolver) (Claims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, ErrMalformed
	}
	hdrBytes, err := b64.DecodeString(parts[0])
	if err != nil {
		return nil, ErrMalformed
	}
	var hdr header
	if err := json.Unmarshal(hdrBytes, &hdr); err != nil {
		return nil, ErrMalformed
	}

	key, err := resolve(hdr.Kid, hdr.Alg)
	if err != nil {
		return nil, err
	}
	sig, err := b64.DecodeString(parts[2])
	if err != nil {
		return nil, ErrMalformed
	}
	signingInput := parts[0] + "." + parts[1]
	if err := verifySignature(hdr.Alg, key, signingInput, sig); err != nil {
		return nil, err
	}

	payload, err := b64.DecodeString(parts[1])
	if err != nil {
		return nil, ErrMalformed
	}
	var claims Claims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, ErrMalformed
	}
	if err := checkTimes(claims); err != nil {
		return nil, err
	}
	return claims, nil
}

var b64 = base64.RawURLEncoding

func verifySignature(alg string, key any, signingInput string, sig []byte) error {
	h, cryptoHash, err := hasherFor(alg)
	if err != nil {
		return err
	}
	h.Write([]byte(signingInput))
	digest := h.Sum(nil)

	switch {
	case strings.HasPrefix(alg, "HS"):
		secret, ok := key.([]byte)
		if !ok {
			return ErrKey
		}
		mac := hmac.New(hashConstructor(cryptoHash), secret)
		mac.Write([]byte(signingInput))
		if hmac.Equal(mac.Sum(nil), sig) {
			return nil
		}
		return ErrSignature
	case strings.HasPrefix(alg, "RS"):
		pub, ok := key.(*rsa.PublicKey)
		if !ok {
			return ErrKey
		}
		if rsa.VerifyPKCS1v15(pub, cryptoHash, digest, sig) == nil {
			return nil
		}
		return ErrSignature
	case strings.HasPrefix(alg, "PS"):
		pub, ok := key.(*rsa.PublicKey)
		if !ok {
			return ErrKey
		}
		if rsa.VerifyPSS(pub, cryptoHash, digest, sig, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash}) == nil {
			return nil
		}
		return ErrSignature
	case strings.HasPrefix(alg, "ES"):
		pub, ok := key.(*ecdsa.PublicKey)
		if !ok {
			return ErrKey
		}
		n := len(sig) / 2
		if n == 0 || len(sig)%2 != 0 {
			return ErrSignature
		}
		r := new(big.Int).SetBytes(sig[:n])
		s := new(big.Int).SetBytes(sig[n:])
		if ecdsa.Verify(pub, digest, r, s) {
			return nil
		}
		return ErrSignature
	default:
		return ErrAlgorithm
	}
}

func hasherFor(alg string) (hash.Hash, crypto.Hash, error) {
	switch {
	case strings.HasSuffix(alg, "256"):
		return sha256.New(), crypto.SHA256, nil
	case strings.HasSuffix(alg, "384"):
		return sha512.New384(), crypto.SHA384, nil
	case strings.HasSuffix(alg, "512"):
		return sha512.New(), crypto.SHA512, nil
	default:
		return nil, 0, ErrAlgorithm
	}
}

func hashConstructor(h crypto.Hash) func() hash.Hash {
	switch h {
	case crypto.SHA384:
		return sha512.New384
	case crypto.SHA512:
		return sha512.New
	default:
		return sha256.New
	}
}

func checkTimes(claims Claims) error {
	now := timeNow().Unix()
	if exp, ok := numeric(claims["exp"]); ok {
		if now > int64(exp)+leewaySeconds {
			return errors.New("jwks: token expired")
		}
	}
	if nbf, ok := numeric(claims["nbf"]); ok {
		if now < int64(nbf)-leewaySeconds {
			return errors.New("jwks: token not yet valid")
		}
	}
	return nil
}

const leewaySeconds = 60

func numeric(v any) (float64, bool) {
	switch n := v.(type) {
	case float64:
		return n, true
	case int64:
		return float64(n), true
	case int:
		return float64(n), true
	default:
		return 0, false
	}
}

// ---- JWK parsing ------------------------------------------------------------

// JWK is a single JSON Web Key.
type JWK struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Alg string `json:"alg"`
	Use string `json:"use"`
	N   string `json:"n"` // RSA modulus (base64url)
	E   string `json:"e"` // RSA exponent (base64url)
	Crv string `json:"crv"`
	X   string `json:"x"` // EC x (base64url)
	Y   string `json:"y"` // EC y (base64url)
}

// Set is a JSON Web Key Set.
type Set struct {
	Keys []JWK `json:"keys"`
}

// PublicKey converts a JWK to a crypto.PublicKey (*rsa.PublicKey or
// *ecdsa.PublicKey).
func (k JWK) PublicKey() (crypto.PublicKey, error) {
	switch k.Kty {
	case "RSA":
		nBytes, err := b64.DecodeString(k.N)
		if err != nil {
			return nil, ErrMalformed
		}
		eBytes, err := b64.DecodeString(k.E)
		if err != nil {
			return nil, ErrMalformed
		}
		e := 0
		for _, b := range eBytes {
			e = e<<8 | int(b)
		}
		return &rsa.PublicKey{N: new(big.Int).SetBytes(nBytes), E: e}, nil
	case "EC":
		xB, err := b64.DecodeString(k.X)
		if err != nil {
			return nil, ErrMalformed
		}
		yB, err := b64.DecodeString(k.Y)
		if err != nil {
			return nil, ErrMalformed
		}
		curve, err := curveFor(k.Crv)
		if err != nil {
			return nil, err
		}
		return &ecdsa.PublicKey{Curve: curve, X: new(big.Int).SetBytes(xB), Y: new(big.Int).SetBytes(yB)}, nil
	default:
		return nil, ErrAlgorithm
	}
}

// Key returns the public key for a kid, or the sole key when kid is empty and
// the set has exactly one key.
func (s *Set) Key(kid string) (crypto.PublicKey, error) {
	for _, k := range s.Keys {
		if k.Kid == kid || (kid == "" && len(s.Keys) == 1) {
			return k.PublicKey()
		}
	}
	return nil, ErrKey
}

// ParseSet parses a JWKS JSON document.
func ParseSet(data []byte) (*Set, error) {
	var set Set
	if err := json.Unmarshal(data, &set); err != nil {
		return nil, err
	}
	return &set, nil
}

// curveFor maps a JWK "crv" name to its elliptic.Curve.
func curveFor(crv string) (elliptic.Curve, error) {
	switch crv {
	case "P-256":
		return elliptic.P256(), nil
	case "P-384":
		return elliptic.P384(), nil
	case "P-521":
		return elliptic.P521(), nil
	default:
		return nil, ErrAlgorithm
	}
}

// timeNow is overridable in tests.
var timeNow = time.Now
