package token

import (
	"encoding/base64"
	"encoding/hex"
	"testing"
)

func TestBytesLengthAndUniqueness(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 100; i++ {
		b, err := Bytes(16)
		if err != nil {
			t.Fatal(err)
		}
		if len(b) != 16 {
			t.Fatalf("len = %d, want 16", len(b))
		}
		if seen[string(b)] {
			t.Fatal("duplicate bytes")
		}
		seen[string(b)] = true
	}
	if _, err := Bytes(0); err == nil {
		t.Error("zero length should error")
	}
}

func TestHex(t *testing.T) {
	s, err := Hex(16)
	if err != nil {
		t.Fatal(err)
	}
	if len(s) != 32 {
		t.Errorf("hex len = %d, want 32", len(s))
	}
	if _, err := hex.DecodeString(s); err != nil {
		t.Errorf("not valid hex: %v", err)
	}
}

func TestURLSafeAndNew(t *testing.T) {
	s, err := URLSafe(32)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := base64.RawURLEncoding.DecodeString(s); err != nil {
		t.Errorf("not valid base64url: %v", err)
	}
	n, err := New()
	if err != nil {
		t.Fatal(err)
	}
	if len(n) == 0 {
		t.Error("New returned empty token")
	}
}

func TestNumeric(t *testing.T) {
	s, err := Numeric(6)
	if err != nil {
		t.Fatal(err)
	}
	if len(s) != 6 {
		t.Errorf("len = %d, want 6", len(s))
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			t.Errorf("non-digit %q in %q", c, s)
		}
	}
	if _, err := Numeric(0); err == nil {
		t.Error("zero digits should error")
	}
}

func TestMustNew(t *testing.T) {
	if got := MustNew(); len(got) == 0 {
		t.Error("MustNew returned empty token")
	}
}

func TestEqual(t *testing.T) {
	if !Equal("secret-token", "secret-token") {
		t.Error("identical tokens should be equal")
	}
	if Equal("secret-token", "secret-toke") {
		t.Error("different-length tokens should not be equal")
	}
	if Equal("aaaa", "bbbb") {
		t.Error("different tokens should not be equal")
	}
}

func BenchmarkURLSafe(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, _ = URLSafe(32)
	}
}
