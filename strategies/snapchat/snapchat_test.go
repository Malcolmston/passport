package snapchat

import "testing"

func TestName(t *testing.T) {
	s := New("id", "secret", "https://app.example/callback", nil)
	if s.Name() != "snapchat" {
		t.Fatalf("Name() = %q, want %q", s.Name(), "snapchat")
	}
}

func TestEndpoints(t *testing.T) {
	s := New("id", "secret", "https://app.example/callback", nil)
	if s.AuthURL() != "https://accounts.snapchat.com/login/oauth2/authorize" {
		t.Errorf("AuthURL() = %q, want %q", s.AuthURL(), "https://accounts.snapchat.com/login/oauth2/authorize")
	}
	if s.TokenURL() != "https://accounts.snapchat.com/login/oauth2/access_token" {
		t.Errorf("TokenURL() = %q, want %q", s.TokenURL(), "https://accounts.snapchat.com/login/oauth2/access_token")
	}
}
