package xero

import "testing"

func TestName(t *testing.T) {
	s := New("id", "secret", "https://app.example/callback", nil)
	if s.Name() != "xero" {
		t.Fatalf("Name() = %q, want %q", s.Name(), "xero")
	}
}

func TestEndpoints(t *testing.T) {
	s := New("id", "secret", "https://app.example/callback", nil)
	if s.AuthURL() != "https://login.xero.com/identity/connect/authorize" {
		t.Errorf("AuthURL() = %q, want %q", s.AuthURL(), "https://login.xero.com/identity/connect/authorize")
	}
	if s.TokenURL() != "https://identity.xero.com/connect/token" {
		t.Errorf("TokenURL() = %q, want %q", s.TokenURL(), "https://identity.xero.com/connect/token")
	}
}
