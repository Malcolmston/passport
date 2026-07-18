package wakatime

import "testing"

func TestName(t *testing.T) {
	s := New("id", "secret", "https://app.example/callback", nil)
	if s.Name() != "wakatime" {
		t.Fatalf("Name() = %q, want %q", s.Name(), "wakatime")
	}
}

func TestEndpoints(t *testing.T) {
	s := New("id", "secret", "https://app.example/callback", nil)
	if s.AuthURL() != "https://wakatime.com/oauth/authorize" {
		t.Errorf("AuthURL() = %q, want %q", s.AuthURL(), "https://wakatime.com/oauth/authorize")
	}
	if s.TokenURL() != "https://wakatime.com/oauth/token" {
		t.Errorf("TokenURL() = %q, want %q", s.TokenURL(), "https://wakatime.com/oauth/token")
	}
}
