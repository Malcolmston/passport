package streamlabs

import "testing"

func TestName(t *testing.T) {
	s := New("id", "secret", "https://app.example/callback", nil)
	if s.Name() != "streamlabs" {
		t.Fatalf("Name() = %q, want %q", s.Name(), "streamlabs")
	}
}

func TestEndpoints(t *testing.T) {
	s := New("id", "secret", "https://app.example/callback", nil)
	if s.AuthURL() != "https://streamlabs.com/api/v2.0/authorize" {
		t.Errorf("AuthURL() = %q, want %q", s.AuthURL(), "https://streamlabs.com/api/v2.0/authorize")
	}
	if s.TokenURL() != "https://streamlabs.com/api/v2.0/token" {
		t.Errorf("TokenURL() = %q, want %q", s.TokenURL(), "https://streamlabs.com/api/v2.0/token")
	}
}
