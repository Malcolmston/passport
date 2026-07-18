package webflow

import "testing"

func TestName(t *testing.T) {
	s := New("id", "secret", "https://app.example/callback", nil)
	if s.Name() != "webflow" {
		t.Fatalf("Name() = %q, want %q", s.Name(), "webflow")
	}
}

func TestEndpoints(t *testing.T) {
	s := New("id", "secret", "https://app.example/callback", nil)
	if s.AuthURL() != "https://webflow.com/oauth/authorize" {
		t.Errorf("AuthURL() = %q, want %q", s.AuthURL(), "https://webflow.com/oauth/authorize")
	}
	if s.TokenURL() != "https://api.webflow.com/oauth/access_token" {
		t.Errorf("TokenURL() = %q, want %q", s.TokenURL(), "https://api.webflow.com/oauth/access_token")
	}
}
