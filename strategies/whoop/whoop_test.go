package whoop

import "testing"

func TestName(t *testing.T) {
	s := New("id", "secret", "https://app.example/callback", nil)
	if s.Name() != "whoop" {
		t.Fatalf("Name() = %q, want %q", s.Name(), "whoop")
	}
}

func TestEndpoints(t *testing.T) {
	s := New("id", "secret", "https://app.example/callback", nil)
	if s.AuthURL() != "https://api.prod.whoop.com/oauth/oauth2/auth" {
		t.Errorf("AuthURL() = %q, want %q", s.AuthURL(), "https://api.prod.whoop.com/oauth/oauth2/auth")
	}
	if s.TokenURL() != "https://api.prod.whoop.com/oauth/oauth2/token" {
		t.Errorf("TokenURL() = %q, want %q", s.TokenURL(), "https://api.prod.whoop.com/oauth/oauth2/token")
	}
}
