package orcid

import "testing"

func TestName(t *testing.T) {
	s := New("id", "secret", "https://app.example/callback", nil)
	if s.Name() != "orcid" {
		t.Fatalf("Name() = %q, want %q", s.Name(), "orcid")
	}
}

func TestEndpoints(t *testing.T) {
	s := New("id", "secret", "https://app.example/callback", nil)
	if s.AuthURL() != "https://orcid.org/oauth/authorize" {
		t.Errorf("AuthURL() = %q, want %q", s.AuthURL(), "https://orcid.org/oauth/authorize")
	}
	if s.TokenURL() != "https://orcid.org/oauth/token" {
		t.Errorf("TokenURL() = %q, want %q", s.TokenURL(), "https://orcid.org/oauth/token")
	}
}
