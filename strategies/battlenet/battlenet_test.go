package battlenet

import "testing"

func TestName(t *testing.T) {
	s := New("id", "secret", "https://app.example/callback", nil)
	if s.Name() != "battlenet" {
		t.Fatalf("Name() = %q, want %q", s.Name(), "battlenet")
	}
}

func TestEndpoints(t *testing.T) {
	s := New("id", "secret", "https://app.example/callback", nil)
	if s.AuthURL() != "https://oauth.battle.net/authorize" {
		t.Errorf("AuthURL() = %q, want %q", s.AuthURL(), "https://oauth.battle.net/authorize")
	}
	if s.TokenURL() != "https://oauth.battle.net/token" {
		t.Errorf("TokenURL() = %q, want %q", s.TokenURL(), "https://oauth.battle.net/token")
	}
}
