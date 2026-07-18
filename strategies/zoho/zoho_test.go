package zoho

import "testing"

func TestName(t *testing.T) {
	s := New("id", "secret", "https://app.example/callback", nil)
	if s.Name() != "zoho" {
		t.Fatalf("Name() = %q, want %q", s.Name(), "zoho")
	}
}

func TestEndpoints(t *testing.T) {
	s := New("id", "secret", "https://app.example/callback", nil)
	if s.AuthURL() != "https://accounts.zoho.com/oauth/v2/auth" {
		t.Errorf("AuthURL() = %q, want %q", s.AuthURL(), "https://accounts.zoho.com/oauth/v2/auth")
	}
	if s.TokenURL() != "https://accounts.zoho.com/oauth/v2/token" {
		t.Errorf("TokenURL() = %q, want %q", s.TokenURL(), "https://accounts.zoho.com/oauth/v2/token")
	}
}
