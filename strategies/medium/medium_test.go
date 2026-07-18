package medium

import "testing"

func TestName(t *testing.T) {
	s := New("id", "secret", "https://app.example/callback", nil)
	if s.Name() != "medium" {
		t.Fatalf("Name() = %q, want %q", s.Name(), "medium")
	}
}

func TestEndpoints(t *testing.T) {
	s := New("id", "secret", "https://app.example/callback", nil)
	if s.AuthURL() != "https://medium.com/m/oauth/authorize" {
		t.Errorf("AuthURL() = %q, want %q", s.AuthURL(), "https://medium.com/m/oauth/authorize")
	}
	if s.TokenURL() != "https://api.medium.com/v1/tokens" {
		t.Errorf("TokenURL() = %q, want %q", s.TokenURL(), "https://api.medium.com/v1/tokens")
	}
}
