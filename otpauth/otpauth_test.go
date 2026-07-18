package otpauth

import (
	"net/url"
	"testing"
)

func TestParseGoogleExample(t *testing.T) {
	raw := "otpauth://totp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP&issuer=Example"
	k, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if k.Type != TOTP {
		t.Errorf("Type = %q", k.Type)
	}
	if k.Issuer != "Example" {
		t.Errorf("Issuer = %q", k.Issuer)
	}
	if k.Account != "alice@google.com" {
		t.Errorf("Account = %q", k.Account)
	}
	if k.Secret != "JBSWY3DPEHPK3PXP" {
		t.Errorf("Secret = %q", k.Secret)
	}
	if k.Algorithm != "SHA1" || k.Digits != 6 || k.Period != 30 {
		t.Errorf("defaults not applied: %+v", k)
	}
}

func TestDecodeSecretKnownValue(t *testing.T) {
	// "JBSWY3DPEHPK3PXP" is the base32 of "Hello!\xDE\xAD\xBE\xEF".
	b, err := DecodeSecret("JBSWY3DPEHPK3PXP")
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != "Hello!\xde\xad\xbe\xef" {
		t.Errorf("decoded = %x", b)
	}
}

func TestURLRoundTrip(t *testing.T) {
	k := Key{
		Type:      TOTP,
		Issuer:    "ACME Co",
		Account:   "john@example.com",
		Secret:    "JBSWY3DPEHPK3PXP",
		Algorithm: "SHA256",
		Digits:    8,
		Period:    60,
	}
	got, err := Parse(k.URL())
	if err != nil {
		t.Fatal(err)
	}
	if got.Issuer != k.Issuer || got.Account != k.Account || got.Secret != k.Secret ||
		got.Algorithm != k.Algorithm || got.Digits != k.Digits || got.Period != k.Period {
		t.Errorf("round trip mismatch:\n have %+v\n want %+v", got, k)
	}
}

func TestHOTPCounter(t *testing.T) {
	k := Key{Type: HOTP, Account: "u", Secret: "JBSWY3DPEHPK3PXP", Counter: 5}
	u := k.URL()
	parsed, err := Parse(u)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Counter != 5 {
		t.Errorf("Counter = %d, want 5", parsed.Counter)
	}
	// Ensure the URL is a valid otpauth HOTP URI carrying the counter.
	pu, _ := url.Parse(u)
	if pu.Host != "hotp" || pu.Query().Get("counter") != "5" {
		t.Errorf("bad HOTP URL: %s", u)
	}
}

func TestParseErrors(t *testing.T) {
	cases := []string{
		"https://totp/foo?secret=ABC",
		"otpauth://unknown/foo?secret=ABC",
		"otpauth://totp/foo",
	}
	for _, c := range cases {
		if _, err := Parse(c); err == nil {
			t.Errorf("Parse(%q) should error", c)
		}
	}
}

func TestLabel(t *testing.T) {
	if l := (Key{Issuer: "I", Account: "a"}).Label(); l != "I:a" {
		t.Errorf("Label = %q", l)
	}
	if l := (Key{Account: "a"}).Label(); l != "a" {
		t.Errorf("Label = %q", l)
	}
}

func TestGenerateSecret(t *testing.T) {
	s, err := GenerateSecret(20)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeSecret(s); err != nil {
		t.Errorf("generated secret not decodable: %v", err)
	}
	if _, err := GenerateSecret(0); err == nil {
		t.Error("zero-length secret should error")
	}
}
