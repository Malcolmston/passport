package oauthstate

import (
	"testing"
	"time"
)

var _ Store = (*MemoryStore)(nil)
var _ Store = (*HMACStore)(nil)

func TestMemoryStoreRoundTrip(t *testing.T) {
	s := NewMemoryStore(time.Minute)
	st, err := s.Issue("return=/dashboard")
	if err != nil {
		t.Fatal(err)
	}
	if s.Len() != 1 {
		t.Errorf("Len = %d, want 1", s.Len())
	}
	payload, err := s.Verify(st)
	if err != nil {
		t.Fatal(err)
	}
	if payload != "return=/dashboard" {
		t.Errorf("payload = %q", payload)
	}
	if s.Len() != 0 {
		t.Errorf("state not consumed, Len = %d", s.Len())
	}
}

func TestMemoryStoreSingleUse(t *testing.T) {
	s := NewMemoryStore(0)
	st, _ := s.Issue("")
	if _, err := s.Verify(st); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Verify(st); err != ErrUnknownState {
		t.Errorf("second Verify err = %v, want ErrUnknownState", err)
	}
	if _, err := s.Verify("never-issued"); err != ErrUnknownState {
		t.Errorf("unknown Verify err = %v", err)
	}
}

func TestMemoryStoreExpiry(t *testing.T) {
	s := NewMemoryStore(time.Hour)
	base := time.Unix(1_700_000_000, 0)
	s.now = func() time.Time { return base }
	st, _ := s.Issue("x")
	s.now = func() time.Time { return base.Add(2 * time.Hour) }
	if _, err := s.Verify(st); err != ErrUnknownState {
		t.Errorf("expired Verify err = %v, want ErrUnknownState", err)
	}
}

func TestHMACStoreRoundTrip(t *testing.T) {
	s := NewHMACStore([]byte("0123456789abcdef0123456789abcdef"), time.Minute)
	st, err := s.Issue("uid=42")
	if err != nil {
		t.Fatal(err)
	}
	payload, err := s.Verify(st)
	if err != nil {
		t.Fatal(err)
	}
	if payload != "uid=42" {
		t.Errorf("payload = %q", payload)
	}
}

func TestHMACStoreTamper(t *testing.T) {
	s := NewHMACStore([]byte("key-key-key-key-key-key-key-key!"), 0)
	st, _ := s.Issue("data")
	// Flip a character in the signed body.
	tampered := "X" + st[1:]
	if _, err := s.Verify(tampered); err != ErrBadSignature {
		t.Errorf("tampered Verify err = %v, want ErrBadSignature", err)
	}
	if _, err := s.Verify("no-dot-here"); err != ErrUnknownState {
		t.Errorf("malformed Verify err = %v", err)
	}
}

func TestHMACStoreWrongKey(t *testing.T) {
	a := NewHMACStore([]byte("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"), 0)
	b := NewHMACStore([]byte("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"), 0)
	st, _ := a.Issue("p")
	if _, err := b.Verify(st); err != ErrBadSignature {
		t.Errorf("cross-key Verify err = %v, want ErrBadSignature", err)
	}
}

func TestHMACStoreExpiry(t *testing.T) {
	s := NewHMACStore([]byte("keykeykeykeykeykeykeykeykeykeyke"), time.Minute)
	base := time.Unix(1_700_000_000, 0)
	s.now = func() time.Time { return base }
	st, _ := s.Issue("p")
	s.now = func() time.Time { return base.Add(2 * time.Minute) }
	if _, err := s.Verify(st); err != ErrUnknownState {
		t.Errorf("expired Verify err = %v, want ErrUnknownState", err)
	}
}

func TestGenerateNonce(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 100; i++ {
		n, err := GenerateNonce()
		if err != nil {
			t.Fatal(err)
		}
		if seen[n] {
			t.Fatalf("duplicate nonce %q", n)
		}
		seen[n] = true
	}
}

func BenchmarkHMACIssueVerify(b *testing.B) {
	s := NewHMACStore([]byte("keykeykeykeykeykeykeykeykeykeyke"), 0)
	for i := 0; i < b.N; i++ {
		st, _ := s.Issue("p")
		_, _ = s.Verify(st)
	}
}
