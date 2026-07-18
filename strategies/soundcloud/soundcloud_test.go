package soundcloud

import "testing"

func TestName(t *testing.T) {
	s := New("id", "secret", "https://app.example/callback", nil)
	if s.Name() != "soundcloud" {
		t.Fatalf("Name() = %q, want %q", s.Name(), "soundcloud")
	}
}

func TestEndpoints(t *testing.T) {
	s := New("id", "secret", "https://app.example/callback", nil)
	if s.AuthURL() != "https://secure.soundcloud.com/authorize" {
		t.Errorf("AuthURL() = %q, want %q", s.AuthURL(), "https://secure.soundcloud.com/authorize")
	}
	if s.TokenURL() != "https://secure.soundcloud.com/oauth/token" {
		t.Errorf("TokenURL() = %q, want %q", s.TokenURL(), "https://secure.soundcloud.com/oauth/token")
	}
}
