package airtable

import "testing"

func TestName(t *testing.T) {
	s := New("id", "secret", "https://app.example/callback", nil)
	if s.Name() != "airtable" {
		t.Fatalf("Name() = %q, want %q", s.Name(), "airtable")
	}
}

func TestEndpoints(t *testing.T) {
	s := New("id", "secret", "https://app.example/callback", nil)
	if s.AuthURL() != "https://airtable.com/oauth2/v1/authorize" {
		t.Errorf("AuthURL() = %q, want %q", s.AuthURL(), "https://airtable.com/oauth2/v1/authorize")
	}
	if s.TokenURL() != "https://airtable.com/oauth2/v1/token" {
		t.Errorf("TokenURL() = %q, want %q", s.TokenURL(), "https://airtable.com/oauth2/v1/token")
	}
}
