package canva

import "testing"

func TestName(t *testing.T) {
	s := New("id", "secret", "https://app.example/callback", nil)
	if s.Name() != "canva" {
		t.Fatalf("Name() = %q, want %q", s.Name(), "canva")
	}
}

func TestEndpoints(t *testing.T) {
	s := New("id", "secret", "https://app.example/callback", nil)
	if s.AuthURL() != "https://www.canva.com/api/oauth/authorize" {
		t.Errorf("AuthURL() = %q, want %q", s.AuthURL(), "https://www.canva.com/api/oauth/authorize")
	}
	if s.TokenURL() != "https://api.canva.com/rest/v1/oauth/token" {
		t.Errorf("TokenURL() = %q, want %q", s.TokenURL(), "https://api.canva.com/rest/v1/oauth/token")
	}
}
