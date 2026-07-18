package ebay

import "testing"

func TestName(t *testing.T) {
	s := New("id", "secret", "https://app.example/callback", nil)
	if s.Name() != "ebay" {
		t.Fatalf("Name() = %q, want %q", s.Name(), "ebay")
	}
}

func TestEndpoints(t *testing.T) {
	s := New("id", "secret", "https://app.example/callback", nil)
	if s.AuthURL() != "https://auth.ebay.com/oauth2/authorize" {
		t.Errorf("AuthURL() = %q, want %q", s.AuthURL(), "https://auth.ebay.com/oauth2/authorize")
	}
	if s.TokenURL() != "https://api.ebay.com/identity/v1/oauth2/token" {
		t.Errorf("TokenURL() = %q, want %q", s.TokenURL(), "https://api.ebay.com/identity/v1/oauth2/token")
	}
}
