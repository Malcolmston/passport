// Package pwhash provides password hashing and verification for the passport
// port using PBKDF2 (RFC 2898 / PKCS #5) over the standard library only. Local
// username/password strategies need a safe way to store and check passwords;
// Node's passport ecosystem leans on modules such as passport-local-mongoose
// for this, and pwhash supplies the equivalent building block here without any
// third-party dependency.
//
// The core Key function is a faithful, allocation-frugal implementation of
// PBKDF2 with an HMAC pseudo-random function, verified against the RFC 6070
// test vectors. On top of it, Hash produces a self-describing, Django-style
// encoded string — "pbkdf2_<hash>$<iterations>$<b64salt>$<b64dk>" — that
// captures every parameter needed to verify it later, and Verify recomputes the
// derived key in constant time. Salting uses crypto/rand; Key itself is
// deterministic.
package pwhash

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"hash"
	"strconv"
	"strings"
)

// Errors returned when decoding or verifying an encoded hash.
var (
	// ErrInvalidHash indicates the encoded string is not a well-formed
	// pwhash value.
	ErrInvalidHash = errors.New("pwhash: malformed encoded hash")

	// ErrUnknownAlgorithm indicates the encoded string names a hash function
	// this package does not support.
	ErrUnknownAlgorithm = errors.New("pwhash: unknown hash algorithm")
)

// MaxIterations is the largest iteration count Decode will accept. Encoded
// hashes are attacker-influenced whenever they reach the process from an
// untrusted store or a copied credential file, and PBKDF2's cost is linear in
// the iteration count, so an unbounded value would let a single Verify call
// pin a CPU indefinitely. The bound is far above any realistic parameter
// choice (DefaultParams uses 600,000).
const MaxIterations = 100_000_000

// Algorithm names the HMAC hash underlying a PBKDF2 derivation.
type Algorithm string

const (
	// SHA1 selects HMAC-SHA1 (the RFC 6070 reference PRF).
	SHA1 Algorithm = "sha1"
	// SHA256 selects HMAC-SHA256, a sensible modern default.
	SHA256 Algorithm = "sha256"
	// SHA512 selects HMAC-SHA512.
	SHA512 Algorithm = "sha512"
)

func (a Algorithm) newHash() (func() hash.Hash, int, bool) {
	switch a {
	case SHA1:
		return sha1.New, sha1.Size, true
	case SHA256:
		return sha256.New, sha256.Size, true
	case SHA512:
		return sha512.New, sha512.Size, true
	default:
		return nil, 0, false
	}
}

// Key derives a keyLen-byte key from password and salt by applying PBKDF2 with
// iter iterations of HMAC using the hash constructed by h. It is a direct
// implementation of the algorithm in RFC 2898 section 5.2 and matches the
// RFC 6070 test vectors for HMAC-SHA1.
//
// keyLen values <= 0 yield an empty key rather than panicking, and iter values
// < 1 are clamped to the RFC's minimum of one iteration. Callers deriving
// password hashes should use Hash/HashWithParams, which pick safe parameters;
// Key is exported for callers that need raw PBKDF2 (for example to match an
// existing hash format).
func Key(password, salt []byte, iter, keyLen int, h func() hash.Hash) []byte {
	if keyLen <= 0 {
		return []byte{}
	}
	if iter < 1 {
		iter = 1
	}
	prf := hmac.New(h, password)
	hLen := prf.Size()
	numBlocks := (keyLen + hLen - 1) / hLen
	dk := make([]byte, 0, numBlocks*hLen)

	var block [4]byte
	u := make([]byte, hLen)
	t := make([]byte, hLen)
	for i := 1; i <= numBlocks; i++ {
		block[0] = byte(i >> 24)
		block[1] = byte(i >> 16)
		block[2] = byte(i >> 8)
		block[3] = byte(i)

		prf.Reset()
		prf.Write(salt)
		prf.Write(block[:])
		u = prf.Sum(u[:0])
		copy(t, u)

		for n := 2; n <= iter; n++ {
			prf.Reset()
			prf.Write(u)
			u = prf.Sum(u[:0])
			for x := range t {
				t[x] ^= u[x]
			}
		}
		dk = append(dk, t...)
	}
	return dk[:keyLen]
}

// Params configures how Hash derives and encodes a password hash.
type Params struct {
	Algorithm  Algorithm // HMAC hash to use (default SHA256 when empty)
	Iterations int       // PBKDF2 iteration count (default 600000 when <= 0)
	SaltLength int       // random salt length in bytes (default 16 when <= 0)
	KeyLength  int       // derived-key length in bytes (default the hash size when <= 0)
}

// DefaultParams returns recommended parameters: HMAC-SHA256, 600,000
// iterations, a 16-byte salt and a 32-byte derived key.
func DefaultParams() Params {
	return Params{Algorithm: SHA256, Iterations: 600_000, SaltLength: 16, KeyLength: sha256.Size}
}

func (p Params) resolve() (Params, func() hash.Hash, error) {
	if p.Algorithm == "" {
		p.Algorithm = SHA256
	}
	h, size, ok := p.Algorithm.newHash()
	if !ok {
		return p, nil, ErrUnknownAlgorithm
	}
	if p.Iterations <= 0 {
		p.Iterations = 600_000
	}
	if p.SaltLength <= 0 {
		p.SaltLength = 16
	}
	if p.KeyLength <= 0 {
		p.KeyLength = size
	}
	return p, h, nil
}

// Hash derives a hash of password under the DefaultParams and returns it as a
// self-describing encoded string that Verify can later check.
func Hash(password string) (string, error) {
	return HashWithParams(password, DefaultParams())
}

// HashWithParams is like Hash but uses the supplied parameters. A fresh random
// salt is generated for every call, so identical passwords yield different
// encodings.
func HashWithParams(password string, p Params) (string, error) {
	p, h, err := p.resolve()
	if err != nil {
		return "", err
	}
	salt := make([]byte, p.SaltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("pwhash: reading random source: %w", err)
	}
	dk := Key([]byte(password), salt, p.Iterations, p.KeyLength, h)
	return encode(p.Algorithm, p.Iterations, salt, dk), nil
}

func encode(alg Algorithm, iter int, salt, dk []byte) string {
	return fmt.Sprintf("pbkdf2_%s$%d$%s$%s",
		alg, iter,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(dk),
	)
}

// Decode parses an encoded pwhash string into its parameters and raw bytes. It
// returns ErrInvalidHash or ErrUnknownAlgorithm on malformed input.
//
// Decode is strict on purpose: an encoding whose salt or derived key is empty,
// whose iteration count is not in [1, MaxIterations], or that carries trailing
// junk is rejected outright rather than being verified against. A hash with an
// empty derived key would otherwise match every password, so this validation is
// load-bearing for Verify's correctness, not merely cosmetic.
func Decode(encoded string) (alg Algorithm, iterations int, salt, dk []byte, err error) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 4 || !strings.HasPrefix(parts[0], "pbkdf2_") {
		return "", 0, nil, nil, ErrInvalidHash
	}
	alg = Algorithm(strings.TrimPrefix(parts[0], "pbkdf2_"))
	if _, _, ok := alg.newHash(); !ok {
		return "", 0, nil, nil, ErrUnknownAlgorithm
	}
	iterations, err = strconv.Atoi(parts[1])
	if err != nil || iterations <= 0 || iterations > MaxIterations {
		return "", 0, nil, nil, ErrInvalidHash
	}
	if salt, err = base64.RawStdEncoding.DecodeString(parts[2]); err != nil {
		return "", 0, nil, nil, ErrInvalidHash
	}
	if dk, err = base64.RawStdEncoding.DecodeString(parts[3]); err != nil {
		return "", 0, nil, nil, ErrInvalidHash
	}
	// A zero-length salt defeats the point of salting, and a zero-length
	// derived key compares equal to every candidate. Neither is producible by
	// HashWithParams, so both indicate corruption or tampering.
	if len(salt) == 0 || len(dk) == 0 {
		return "", 0, nil, nil, ErrInvalidHash
	}
	return alg, iterations, salt, dk, nil
}

// Verify reports whether password matches the given encoded hash. The
// comparison of derived keys is constant-time. A malformed encoding returns a
// non-nil error and a false result; callers must treat a non-nil error as a
// failed login and never fall through to success.
func Verify(password, encoded string) (bool, error) {
	alg, iter, salt, dk, err := Decode(encoded)
	if err != nil {
		return false, err
	}
	// Decode guarantees len(dk) > 0; re-checking keeps the invariant local so a
	// future change to Decode cannot silently reintroduce a match-anything hash
	// (ConstantTimeCompare reports equality for two empty slices).
	if len(dk) == 0 {
		return false, ErrInvalidHash
	}
	h, _, _ := alg.newHash()
	computed := Key([]byte(password), salt, iter, len(dk), h)
	return subtle.ConstantTimeCompare(computed, dk) == 1, nil
}

// NeedsRehash reports whether an encoded hash was produced with weaker
// parameters than want, meaning the stored credential should be re-derived the
// next time the plaintext password is available (i.e. immediately after a
// successful Verify). It mirrors the upgrade hook password libraries expose —
// Django's check_password/must_update and PHP's password_needs_rehash — and
// lets a deployment raise its iteration count without forcing a reset.
//
// A hash that cannot be decoded needs rehashing by definition, so NeedsRehash
// returns true for malformed input.
func NeedsRehash(encoded string, want Params) bool {
	want, _, err := want.resolve()
	if err != nil {
		return true
	}
	alg, iter, salt, dk, err := Decode(encoded)
	if err != nil {
		return true
	}
	return alg != want.Algorithm ||
		iter < want.Iterations ||
		len(salt) < want.SaltLength ||
		len(dk) < want.KeyLength
}
