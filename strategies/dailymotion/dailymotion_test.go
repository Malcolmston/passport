package dailymotion

import "testing"

func TestName(t *testing.T) {
	s := New("id", "secret", "https://app.example/callback", nil)
	if s.Name() != "dailymotion" {
		t.Fatalf("Name() = %q, want %q", s.Name(), "dailymotion")
	}
}

func TestEndpoints(t *testing.T) {
	s := New("id", "secret", "https://app.example/callback", nil)
	if s.AuthURL() != "https://www.dailymotion.com/oauth/authorize" {
		t.Errorf("AuthURL() = %q, want %q", s.AuthURL(), "https://www.dailymotion.com/oauth/authorize")
	}
	if s.TokenURL() != "https://api.dailymotion.com/oauth/token" {
		t.Errorf("TokenURL() = %q, want %q", s.TokenURL(), "https://api.dailymotion.com/oauth/token")
	}
}
