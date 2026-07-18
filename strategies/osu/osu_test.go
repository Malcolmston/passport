package osu

import "testing"

func TestName(t *testing.T) {
	s := New("id", "secret", "https://app.example/callback", nil)
	if s.Name() != "osu" {
		t.Fatalf("Name() = %q, want %q", s.Name(), "osu")
	}
}

func TestEndpoints(t *testing.T) {
	s := New("id", "secret", "https://app.example/callback", nil)
	if s.AuthURL() != "https://osu.ppy.sh/oauth/authorize" {
		t.Errorf("AuthURL() = %q, want %q", s.AuthURL(), "https://osu.ppy.sh/oauth/authorize")
	}
	if s.TokenURL() != "https://osu.ppy.sh/oauth/token" {
		t.Errorf("TokenURL() = %q, want %q", s.TokenURL(), "https://osu.ppy.sh/oauth/token")
	}
}
