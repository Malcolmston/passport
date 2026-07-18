package nightbot

import "testing"

func TestName(t *testing.T) {
	s := New("id", "secret", "https://app.example/callback", nil)
	if s.Name() != "nightbot" {
		t.Fatalf("Name() = %q, want %q", s.Name(), "nightbot")
	}
}

func TestEndpoints(t *testing.T) {
	s := New("id", "secret", "https://app.example/callback", nil)
	if s.AuthURL() != "https://api.nightbot.tv/oauth2/authorize" {
		t.Errorf("AuthURL() = %q, want %q", s.AuthURL(), "https://api.nightbot.tv/oauth2/authorize")
	}
	if s.TokenURL() != "https://api.nightbot.tv/oauth2/token" {
		t.Errorf("TokenURL() = %q, want %q", s.TokenURL(), "https://api.nightbot.tv/oauth2/token")
	}
}
