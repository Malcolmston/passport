package buffer

import "testing"

func TestName(t *testing.T) {
	s := New("id", "secret", "https://app.example/callback", nil)
	if s.Name() != "buffer" {
		t.Fatalf("Name() = %q, want %q", s.Name(), "buffer")
	}
}

func TestEndpoints(t *testing.T) {
	s := New("id", "secret", "https://app.example/callback", nil)
	if s.AuthURL() != "https://bufferapp.com/oauth2/authorize" {
		t.Errorf("AuthURL() = %q, want %q", s.AuthURL(), "https://bufferapp.com/oauth2/authorize")
	}
	if s.TokenURL() != "https://api.bufferapp.com/1/oauth2/token.json" {
		t.Errorf("TokenURL() = %q, want %q", s.TokenURL(), "https://api.bufferapp.com/1/oauth2/token.json")
	}
}
