package linear

import "testing"

func TestName(t *testing.T) {
	s := New("id", "secret", "https://app.example/callback", nil)
	if s.Name() != "linear" {
		t.Fatalf("Name() = %q, want %q", s.Name(), "linear")
	}
}

func TestEndpoints(t *testing.T) {
	s := New("id", "secret", "https://app.example/callback", nil)
	if s.AuthURL() != "https://linear.app/oauth/authorize" {
		t.Errorf("AuthURL() = %q, want %q", s.AuthURL(), "https://linear.app/oauth/authorize")
	}
	if s.TokenURL() != "https://api.linear.app/oauth/token" {
		t.Errorf("TokenURL() = %q, want %q", s.TokenURL(), "https://api.linear.app/oauth/token")
	}
}
