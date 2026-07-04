package workos

import "testing"

func TestName(t *testing.T) {
	s := New("id", "secret", "https://app.example/callback", nil)
	if s.Name() != "workos" {
		t.Fatalf("Name() = %q, want %q", s.Name(), "workos")
	}
}
