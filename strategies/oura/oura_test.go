package oura

import "testing"

func TestName(t *testing.T) {
	s := New("id", "secret", "https://app.example/callback", nil)
	if s.Name() != "oura" {
		t.Fatalf("Name() = %q, want %q", s.Name(), "oura")
	}
}

func TestEndpoints(t *testing.T) {
	s := New("id", "secret", "https://app.example/callback", nil)
	if s.AuthURL() != "https://cloud.ouraring.com/oauth/authorize" {
		t.Errorf("AuthURL() = %q, want %q", s.AuthURL(), "https://cloud.ouraring.com/oauth/authorize")
	}
	if s.TokenURL() != "https://api.ouraring.com/oauth/token" {
		t.Errorf("TokenURL() = %q, want %q", s.TokenURL(), "https://api.ouraring.com/oauth/token")
	}
}
