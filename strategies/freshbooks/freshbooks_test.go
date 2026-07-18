package freshbooks

import "testing"

func TestName(t *testing.T) {
	s := New("id", "secret", "https://app.example/callback", nil)
	if s.Name() != "freshbooks" {
		t.Fatalf("Name() = %q, want %q", s.Name(), "freshbooks")
	}
}

func TestEndpoints(t *testing.T) {
	s := New("id", "secret", "https://app.example/callback", nil)
	if s.AuthURL() != "https://auth.freshbooks.com/oauth/authorize" {
		t.Errorf("AuthURL() = %q, want %q", s.AuthURL(), "https://auth.freshbooks.com/oauth/authorize")
	}
	if s.TokenURL() != "https://api.freshbooks.com/auth/oauth/token" {
		t.Errorf("TokenURL() = %q, want %q", s.TokenURL(), "https://api.freshbooks.com/auth/oauth/token")
	}
}
