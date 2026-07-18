package sentry

import "testing"

func TestName(t *testing.T) {
	s := New("id", "secret", "https://app.example/callback", nil)
	if s.Name() != "sentry" {
		t.Fatalf("Name() = %q, want %q", s.Name(), "sentry")
	}
}

func TestEndpoints(t *testing.T) {
	s := New("id", "secret", "https://app.example/callback", nil)
	if s.AuthURL() != "https://sentry.io/oauth/authorize/" {
		t.Errorf("AuthURL() = %q, want %q", s.AuthURL(), "https://sentry.io/oauth/authorize/")
	}
	if s.TokenURL() != "https://sentry.io/oauth/token/" {
		t.Errorf("TokenURL() = %q, want %q", s.TokenURL(), "https://sentry.io/oauth/token/")
	}
}
