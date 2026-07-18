package yahoo

import "testing"

func TestName(t *testing.T) {
	s := New("id", "secret", "https://app.example/callback", nil)
	if s.Name() != "yahoo" {
		t.Fatalf("Name() = %q, want %q", s.Name(), "yahoo")
	}
}

func TestEndpoints(t *testing.T) {
	s := New("id", "secret", "https://app.example/callback", nil)
	if s.AuthURL() != "https://api.login.yahoo.com/oauth2/request_auth" {
		t.Errorf("AuthURL() = %q, want %q", s.AuthURL(), "https://api.login.yahoo.com/oauth2/request_auth")
	}
	if s.TokenURL() != "https://api.login.yahoo.com/oauth2/get_token" {
		t.Errorf("TokenURL() = %q, want %q", s.TokenURL(), "https://api.login.yahoo.com/oauth2/get_token")
	}
}
