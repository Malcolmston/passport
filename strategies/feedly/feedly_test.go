package feedly

import "testing"

func TestName(t *testing.T) {
	s := New("id", "secret", "https://app.example/callback", nil)
	if s.Name() != "feedly" {
		t.Fatalf("Name() = %q, want %q", s.Name(), "feedly")
	}
}

func TestEndpoints(t *testing.T) {
	s := New("id", "secret", "https://app.example/callback", nil)
	if s.AuthURL() != "https://feedly.com/v3/auth/auth" {
		t.Errorf("AuthURL() = %q, want %q", s.AuthURL(), "https://feedly.com/v3/auth/auth")
	}
	if s.TokenURL() != "https://feedly.com/v3/auth/token" {
		t.Errorf("TokenURL() = %q, want %q", s.TokenURL(), "https://feedly.com/v3/auth/token")
	}
}
