package otpauth

// Parity tests against the CANONICAL specification vectors for the OTP
// ecosystem this package serves:
//
//   - RFC 4226 (HOTP) Appendix D  — https://www.rfc-editor.org/rfc/rfc4226#appendix-D
//   - RFC 6238 (TOTP) Appendix B  — https://www.rfc-editor.org/rfc/rfc6238#appendix-B
//   - Key Uri Format             — https://github.com/google/google-authenticator/wiki/Key-Uri-Format
//   - hectorm/otpauth test suite — https://raw.githubusercontent.com/hectorm/otpauth/master/test/test.mjs
//
// This package does not itself compute OTP codes (that lives in the passport
// strategies); its job is the otpauth:// URI format and base32 secret handling.
// These tests therefore verify two things end to end:
//
//  1. DecodeSecret turns the famous base32-encoded RFC seeds back into the exact
//     ASCII seed bytes, and those bytes, fed through the RFC HOTP/TOTP algorithm
//     (implemented inline here from crypto/* stdlib as the authoritative oracle),
//     reproduce every canonical Appendix D / Appendix B code. This proves the
//     package's secret decoding interoperates with real RFC generators.
//  2. Parse and URL round-trip the canonical Key Uri Format strings.

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"fmt"
	"hash"
	"net/url"
	"strings"
	"testing"
)

// rfcHOTP is the RFC 4226 §5.3 truncation algorithm, used here only as the
// authoritative oracle for the canonical vectors (stdlib crypto only).
func rfcHOTP(key []byte, counter uint64, digits int, h func() hash.Hash) string {
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, counter)
	m := hmac.New(h, key)
	m.Write(buf)
	sum := m.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	code := (uint32(sum[off]&0x7f) << 24) |
		(uint32(sum[off+1]) << 16) |
		(uint32(sum[off+2]) << 8) |
		uint32(sum[off+3])
	mod := uint32(1)
	for i := 0; i < digits; i++ {
		mod *= 10
	}
	return fmt.Sprintf("%0*d", digits, code%mod)
}

// The canonical base32 (RFC 4648, no padding) encodings of the RFC seeds.
// These are the fixed, well-known secrets every RFC 4226/6238 vector uses.
const (
	// ASCII "12345678901234567890" (20 bytes) — SHA1 seed.
	seedSHA1B32 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
	// ASCII "12345678901234567890123456789012" (32 bytes) — SHA256 seed.
	seedSHA256B32 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA"
	// ASCII "1234...1234" (64 bytes) — SHA512 seed.
	seedSHA512B32 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNA"
)

// TestParityRFCSeedDecode: DecodeSecret of each canonical base32 seed must yield
// the exact ASCII seed bytes given in RFC 6238 Appendix B.
func TestParityRFCSeedDecode(t *testing.T) {
	cases := []struct {
		name, b32, want string
	}{
		{"SHA1-20B", seedSHA1B32, "12345678901234567890"},
		{"SHA256-32B", seedSHA256B32, "12345678901234567890123456789012"},
		{"SHA512-64B", seedSHA512B32, "1234567890123456789012345678901234567890123456789012345678901234"},
	}
	for _, c := range cases {
		b, err := DecodeSecret(c.b32)
		if err != nil {
			t.Fatalf("%s: DecodeSecret error: %v", c.name, err)
		}
		if string(b) != c.want {
			t.Errorf("%s: DecodeSecret = %q, want %q", c.name, b, c.want)
		}
	}
	// DecodeSecret must also tolerate lowercase, padding and spaces (the forms
	// authenticator apps and users produce) and still land on the same bytes.
	variants := []string{
		strings.ToLower(seedSHA1B32),
		"gezd gnbv gy3t qojq gezd gnbv gy3t qojq",
		seedSHA1B32 + "======",
	}
	for _, v := range variants {
		b, err := DecodeSecret(v)
		if err != nil {
			t.Fatalf("DecodeSecret(%q) error: %v", v, err)
		}
		if string(b) != "12345678901234567890" {
			t.Errorf("DecodeSecret(%q) = %q, want the SHA1 seed", v, b)
		}
	}
}

// TestParityRFC4226HOTP: RFC 4226 Appendix D — HOTP(secret, count=0..9), 6 digits.
func TestParityRFC4226HOTP(t *testing.T) {
	key, err := DecodeSecret(seedSHA1B32)
	if err != nil {
		t.Fatalf("DecodeSecret: %v", err)
	}
	want := []string{
		"755224", "287082", "359152", "969429", "338314",
		"254676", "287922", "162583", "399871", "520489",
	}
	for count, exp := range want {
		got := rfcHOTP(key, uint64(count), 6, sha1.New)
		if got != exp {
			t.Errorf("HOTP count=%d = %s, want %s", count, got, exp)
		}
	}
}

// TestParityRFC6238TOTP: RFC 6238 Appendix B — TOTP at fixed Unix times, 8 digits,
// step 30s, for SHA1 (20B), SHA256 (32B) and SHA512 (64B) seeds.
func TestParityRFC6238TOTP(t *testing.T) {
	k1, _ := DecodeSecret(seedSHA1B32)
	k256, _ := DecodeSecret(seedSHA256B32)
	k512, _ := DecodeSecret(seedSHA512B32)

	type row struct {
		unix                     int64
		sha1, sha256, sha512Want string
	}
	rows := []row{
		{59, "94287082", "46119246", "90693936"},
		{1111111109, "07081804", "68084774", "25091201"},
		{1111111111, "14050471", "67062674", "99943326"},
		{1234567890, "89005924", "91819424", "93441116"},
		{2000000000, "69279037", "90698825", "38618901"},
		{20000000000, "65353130", "77737706", "47863826"},
	}
	for _, r := range rows {
		ctr := uint64(r.unix / 30)
		if got := rfcHOTP(k1, ctr, 8, sha1.New); got != r.sha1 {
			t.Errorf("TOTP SHA1 T=%d = %s, want %s", r.unix, got, r.sha1)
		}
		if got := rfcHOTP(k256, ctr, 8, sha256.New); got != r.sha256 {
			t.Errorf("TOTP SHA256 T=%d = %s, want %s", r.unix, got, r.sha256)
		}
		if got := rfcHOTP(k512, ctr, 8, sha512.New); got != r.sha512Want {
			t.Errorf("TOTP SHA512 T=%d = %s, want %s", r.unix, got, r.sha512Want)
		}
	}
}

// TestParityKeyUriParse: canonical Key Uri Format strings must parse into the
// documented fields, applying the format defaults for omitted parameters.
func TestParityKeyUriParse(t *testing.T) {
	// Google Authenticator wiki canonical TOTP example.
	k, err := Parse("otpauth://totp/ACME%20Co:john.doe@email.com?" +
		"secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ&issuer=ACME%20Co&algorithm=SHA1&digits=6&period=30")
	if err != nil {
		t.Fatalf("Parse ACME: %v", err)
	}
	if k.Type != TOTP || k.Issuer != "ACME Co" || k.Account != "john.doe@email.com" ||
		k.Secret != "HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ" ||
		k.Algorithm != "SHA1" || k.Digits != 6 || k.Period != 30 {
		t.Errorf("Parse ACME mismatch: %+v", k)
	}

	// Minimal wiki example: defaults must be filled in.
	k2, err := Parse("otpauth://totp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP&issuer=Example")
	if err != nil {
		t.Fatalf("Parse Example: %v", err)
	}
	if k2.Issuer != "Example" || k2.Account != "alice@google.com" ||
		k2.Algorithm != "SHA1" || k2.Digits != 6 || k2.Period != 30 {
		t.Errorf("Parse Example defaults: %+v", k2)
	}

	// HOTP with counter; period must not be set for HOTP.
	k3, err := Parse("otpauth://hotp/ACME%20Co:john.doe@email.com?" +
		"secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ&issuer=ACME%20Co&algorithm=SHA1&digits=8&counter=0")
	if err != nil {
		t.Fatalf("Parse HOTP: %v", err)
	}
	if k3.Type != HOTP || k3.Digits != 8 || k3.Counter != 0 || k3.Period != 0 {
		t.Errorf("Parse HOTP mismatch: %+v", k3)
	}
}

// TestParityKeyUriBuild: URL() must emit a canonical Key Uri Format string.
// Per the format, spaces are percent-encoded (%20) everywhere, including the
// query — a literal "+" is displayed verbatim by some authenticator apps and is
// not a spec-canonical space encoding.
func TestParityKeyUriBuild(t *testing.T) {
	k := Key{
		Type:    TOTP,
		Issuer:  "ACME Co",
		Account: "john.doe@email.com",
		Secret:  "HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ",
	}
	got := k.URL()
	if strings.Contains(got, "+") {
		t.Errorf("URL() encodes a space as '+', want %%20 per Key Uri Format: %s", got)
	}
	if !strings.Contains(got, "issuer=ACME%20Co") {
		t.Errorf("URL() issuer not %%20-encoded: %s", got)
	}
	// The label prefix must also be %20-encoded and round-trip cleanly.
	if !strings.HasPrefix(got, "otpauth://totp/ACME%20Co:john.doe@email.com?") {
		t.Errorf("URL() label mismatch: %s", got)
	}
	back, err := Parse(got)
	if err != nil {
		t.Fatalf("re-Parse: %v", err)
	}
	if back.Issuer != "ACME Co" || back.Account != "john.doe@email.com" || back.Secret != k.Secret {
		t.Errorf("round-trip mismatch: %+v", back)
	}

	// Sanity: the query must be genuinely valid — the issuer decodes to a space.
	pu, _ := url.Parse(got)
	if pu.Query().Get("issuer") != "ACME Co" {
		t.Errorf("query issuer = %q, want %q", pu.Query().Get("issuer"), "ACME Co")
	}
}
