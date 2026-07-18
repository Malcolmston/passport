package webex

import "testing"

func TestName(t *testing.T) {
	s := New("id", "secret", "https://app.example/callback", nil)
	if s.Name() != "webex" {
		t.Fatalf("Name() = %q, want %q", s.Name(), "webex")
	}
}

func TestEndpoints(t *testing.T) {
	s := New("id", "secret", "https://app.example/callback", nil)
	if s.AuthURL() != "https://webexapis.com/v1/authorize" {
		t.Errorf("AuthURL() = %q, want %q", s.AuthURL(), "https://webexapis.com/v1/authorize")
	}
	if s.TokenURL() != "https://webexapis.com/v1/access_token" {
		t.Errorf("TokenURL() = %q, want %q", s.TokenURL(), "https://webexapis.com/v1/access_token")
	}
}
