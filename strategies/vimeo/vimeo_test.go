package vimeo

import "testing"

func TestName(t *testing.T) {
	s := New("id", "secret", "https://app.example/callback", nil)
	if s.Name() != "vimeo" {
		t.Fatalf("Name() = %q, want %q", s.Name(), "vimeo")
	}
}

func TestEndpoints(t *testing.T) {
	s := New("id", "secret", "https://app.example/callback", nil)
	if s.AuthURL() != "https://api.vimeo.com/oauth/authorize" {
		t.Errorf("AuthURL() = %q, want %q", s.AuthURL(), "https://api.vimeo.com/oauth/authorize")
	}
	if s.TokenURL() != "https://api.vimeo.com/oauth/access_token" {
		t.Errorf("TokenURL() = %q, want %q", s.TokenURL(), "https://api.vimeo.com/oauth/access_token")
	}
}
