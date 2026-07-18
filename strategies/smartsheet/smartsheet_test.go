package smartsheet

import "testing"

func TestName(t *testing.T) {
	s := New("id", "secret", "https://app.example/callback", nil)
	if s.Name() != "smartsheet" {
		t.Fatalf("Name() = %q, want %q", s.Name(), "smartsheet")
	}
}

func TestEndpoints(t *testing.T) {
	s := New("id", "secret", "https://app.example/callback", nil)
	if s.AuthURL() != "https://app.smartsheet.com/b/authorize" {
		t.Errorf("AuthURL() = %q, want %q", s.AuthURL(), "https://app.smartsheet.com/b/authorize")
	}
	if s.TokenURL() != "https://api.smartsheet.com/2.0/token" {
		t.Errorf("TokenURL() = %q, want %q", s.TokenURL(), "https://api.smartsheet.com/2.0/token")
	}
}
