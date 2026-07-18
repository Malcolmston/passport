package epicgames

import "testing"

func TestName(t *testing.T) {
	s := New("id", "secret", "https://app.example/callback", nil)
	if s.Name() != "epicgames" {
		t.Fatalf("Name() = %q, want %q", s.Name(), "epicgames")
	}
}

func TestEndpoints(t *testing.T) {
	s := New("id", "secret", "https://app.example/callback", nil)
	if s.AuthURL() != "https://www.epicgames.com/id/authorize" {
		t.Errorf("AuthURL() = %q, want %q", s.AuthURL(), "https://www.epicgames.com/id/authorize")
	}
	if s.TokenURL() != "https://api.epicgames.dev/epic/oauth/v1/token" {
		t.Errorf("TokenURL() = %q, want %q", s.TokenURL(), "https://api.epicgames.dev/epic/oauth/v1/token")
	}
}
