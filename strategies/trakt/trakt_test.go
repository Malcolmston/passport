package trakt

import "testing"

func TestName(t *testing.T) {
	s := New("id", "secret", "https://app.example/callback", nil)
	if s.Name() != "trakt" {
		t.Fatalf("Name() = %q, want %q", s.Name(), "trakt")
	}
}

func TestEndpoints(t *testing.T) {
	s := New("id", "secret", "https://app.example/callback", nil)
	if s.AuthURL() != "https://trakt.tv/oauth/authorize" {
		t.Errorf("AuthURL() = %q, want %q", s.AuthURL(), "https://trakt.tv/oauth/authorize")
	}
	if s.TokenURL() != "https://api.trakt.tv/oauth/token" {
		t.Errorf("TokenURL() = %q, want %q", s.TokenURL(), "https://api.trakt.tv/oauth/token")
	}
}
