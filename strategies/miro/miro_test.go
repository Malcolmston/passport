package miro

import "testing"

func TestName(t *testing.T) {
	s := New("id", "secret", "https://app.example/callback", nil)
	if s.Name() != "miro" {
		t.Fatalf("Name() = %q, want %q", s.Name(), "miro")
	}
}

func TestEndpoints(t *testing.T) {
	s := New("id", "secret", "https://app.example/callback", nil)
	if s.AuthURL() != "https://miro.com/oauth/authorize" {
		t.Errorf("AuthURL() = %q, want %q", s.AuthURL(), "https://miro.com/oauth/authorize")
	}
	if s.TokenURL() != "https://api.miro.com/v1/oauth/token" {
		t.Errorf("TokenURL() = %q, want %q", s.TokenURL(), "https://api.miro.com/v1/oauth/token")
	}
}
