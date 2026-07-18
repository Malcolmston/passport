package unsplash

import "testing"

func TestName(t *testing.T) {
	s := New("id", "secret", "https://app.example/callback", nil)
	if s.Name() != "unsplash" {
		t.Fatalf("Name() = %q, want %q", s.Name(), "unsplash")
	}
}

func TestEndpoints(t *testing.T) {
	s := New("id", "secret", "https://app.example/callback", nil)
	if s.AuthURL() != "https://unsplash.com/oauth/authorize" {
		t.Errorf("AuthURL() = %q, want %q", s.AuthURL(), "https://unsplash.com/oauth/authorize")
	}
	if s.TokenURL() != "https://unsplash.com/oauth/token" {
		t.Errorf("TokenURL() = %q, want %q", s.TokenURL(), "https://unsplash.com/oauth/token")
	}
}
