package calendly

import "testing"

func TestName(t *testing.T) {
	s := New("id", "secret", "https://app.example/callback", nil)
	if s.Name() != "calendly" {
		t.Fatalf("Name() = %q, want %q", s.Name(), "calendly")
	}
}

func TestEndpoints(t *testing.T) {
	s := New("id", "secret", "https://app.example/callback", nil)
	if s.AuthURL() != "https://auth.calendly.com/oauth/authorize" {
		t.Errorf("AuthURL() = %q, want %q", s.AuthURL(), "https://auth.calendly.com/oauth/authorize")
	}
	if s.TokenURL() != "https://auth.calendly.com/oauth/token" {
		t.Errorf("TokenURL() = %q, want %q", s.TokenURL(), "https://auth.calendly.com/oauth/token")
	}
}
