package openstreetmap

import "testing"

func TestName(t *testing.T) {
	s := New("id", "secret", "https://app.example/callback", nil)
	if s.Name() != "openstreetmap" {
		t.Fatalf("Name() = %q, want %q", s.Name(), "openstreetmap")
	}
}

func TestEndpoints(t *testing.T) {
	s := New("id", "secret", "https://app.example/callback", nil)
	if s.AuthURL() != "https://www.openstreetmap.org/oauth2/authorize" {
		t.Errorf("AuthURL() = %q, want %q", s.AuthURL(), "https://www.openstreetmap.org/oauth2/authorize")
	}
	if s.TokenURL() != "https://www.openstreetmap.org/oauth2/token" {
		t.Errorf("TokenURL() = %q, want %q", s.TokenURL(), "https://www.openstreetmap.org/oauth2/token")
	}
}
