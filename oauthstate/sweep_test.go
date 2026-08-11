package oauthstate

import (
	"testing"
	"time"
)

// TestSweepBoundsMemory pins the fix for unbounded growth. Most OAuth states
// are never redeemed — users abandon consent screens — so without expiry
// collection a long-running store keeps every one of them forever.
func TestSweepBoundsMemory(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	s := NewMemoryStore(time.Minute)
	s.now = func() time.Time { return now }

	// Issue enough states to cross several automatic sweep points, advancing
	// the clock so earlier ones expire along the way.
	for i := 0; i < 10*sweepEvery; i++ {
		if _, err := s.Issue("payload"); err != nil {
			t.Fatal(err)
		}
		now = now.Add(time.Second)
	}

	// Everything issued more than a minute ago should already be gone, so the
	// store holds roughly a minute's worth rather than all 640.
	if got := s.Len(); got > 2*sweepEvery {
		t.Errorf("store holds %d entries after 10*%d issues; automatic sweeping is not working", got, sweepEvery)
	}

	// An explicit Sweep drops the rest once they age out.
	now = now.Add(time.Hour)
	if s.Sweep() == 0 && s.Len() != 0 {
		t.Error("Sweep removed nothing but entries remain")
	}
	if got := s.Len(); got != 0 {
		t.Errorf("Len() = %d after sweeping an hour later, want 0", got)
	}
}

// TestSweepIgnoresUnexpiringStores confirms a store with no TTL is left alone.
func TestSweepIgnoresUnexpiringStores(t *testing.T) {
	s := NewMemoryStore(0)
	for i := 0; i < 5; i++ {
		if _, err := s.Issue(""); err != nil {
			t.Fatal(err)
		}
	}
	if n := s.Sweep(); n != 0 {
		t.Errorf("Sweep removed %d entries from a store with no TTL", n)
	}
	if s.Len() != 5 {
		t.Errorf("Len() = %d, want 5", s.Len())
	}
}

// TestSweepKeepsLiveStatesRedeemable makes sure sweeping never eats a state
// that is still within its TTL.
func TestSweepKeepsLiveStatesRedeemable(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	s := NewMemoryStore(time.Minute)
	s.now = func() time.Time { return now }

	live, err := s.Issue("keep-me")
	if err != nil {
		t.Fatal(err)
	}
	now = now.Add(30 * time.Second)
	s.Sweep()

	payload, err := s.Verify(live)
	if err != nil {
		t.Fatalf("a state inside its TTL was swept: %v", err)
	}
	if payload != "keep-me" {
		t.Errorf("payload = %q", payload)
	}
}

// TestHMACStoreRejectsMalformedTimestamp pins the switch from fmt.Sscanf to
// strconv: Sscanf("12x", "%d") succeeds and drops the trailing bytes, so a
// timestamp with garbage appended used to pass the expiry check.
func TestHMACStoreRejectsMalformedTimestamp(t *testing.T) {
	s := NewHMACStore([]byte("key-of-at-least-32-bytes-for-hmac!"), time.Minute)

	// Forge a body whose timestamp is "<now>x" and sign it properly, so only
	// the timestamp parsing can reject it.
	body := "nonce." + b64enc(itoa(s.now().Unix())+"x") + "." + b64enc("payload")
	state := body + "." + s.sign(body)

	if _, err := s.Verify(state); err == nil {
		t.Error("a state with a trailing-garbage timestamp must be rejected")
	}
}

// TestEqualConstantTime checks the exported comparison helper.
func TestEqualConstantTime(t *testing.T) {
	for _, tt := range []struct {
		a, b string
		want bool
	}{
		{"abc", "abc", true},
		{"abc", "abd", false},
		{"abc", "ab", false},
		{"", "", true},
		{"", "a", false},
	} {
		if got := Equal(tt.a, tt.b); got != tt.want {
			t.Errorf("Equal(%q,%q) = %v, want %v", tt.a, tt.b, got, tt.want)
		}
	}
}

// TestGenerateNonceWithLength covers the entropy-size boundary.
func TestGenerateNonceWithLength(t *testing.T) {
	if _, err := GenerateNonceWithLength(0); err == nil {
		t.Error("zero entropy must be rejected")
	}
	if _, err := GenerateNonceWithLength(-1); err == nil {
		t.Error("negative entropy must be rejected")
	}
	seen := map[string]bool{}
	for i := 0; i < 100; i++ {
		n, err := GenerateNonceWithLength(32)
		if err != nil {
			t.Fatal(err)
		}
		if seen[n] {
			t.Fatal("GenerateNonceWithLength repeated a value; it is not random")
		}
		seen[n] = true
	}
}
