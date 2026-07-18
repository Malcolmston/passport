package producthunt

import "testing"

func TestName(t *testing.T) {
	s := New("id", "secret", "https://app.example/callback", nil)
	if s.Name() != "producthunt" {
		t.Fatalf("Name() = %q, want %q", s.Name(), "producthunt")
	}
}

func TestEndpoints(t *testing.T) {
	s := New("id", "secret", "https://app.example/callback", nil)
	if s.AuthURL() != "https://api.producthunt.com/v2/oauth/authorize" {
		t.Errorf("AuthURL() = %q, want %q", s.AuthURL(), "https://api.producthunt.com/v2/oauth/authorize")
	}
	if s.TokenURL() != "https://api.producthunt.com/v2/oauth/token" {
		t.Errorf("TokenURL() = %q, want %q", s.TokenURL(), "https://api.producthunt.com/v2/oauth/token")
	}
}
