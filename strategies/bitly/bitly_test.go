package bitly

import "testing"

func TestName(t *testing.T) {
	s := New("id", "secret", "https://app.example/callback", nil)
	if s.Name() != "bitly" {
		t.Fatalf("Name() = %q, want %q", s.Name(), "bitly")
	}
}

func TestEndpoints(t *testing.T) {
	s := New("id", "secret", "https://app.example/callback", nil)
	if s.AuthURL() != "https://bitly.com/oauth/authorize" {
		t.Errorf("AuthURL() = %q, want %q", s.AuthURL(), "https://bitly.com/oauth/authorize")
	}
	if s.TokenURL() != "https://api-ssl.bitly.com/oauth/access_token" {
		t.Errorf("TokenURL() = %q, want %q", s.TokenURL(), "https://api-ssl.bitly.com/oauth/access_token")
	}
}
