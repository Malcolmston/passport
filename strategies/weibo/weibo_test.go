package weibo

import "testing"

func TestName(t *testing.T) {
	s := New("id", "secret", "https://app.example/callback", nil)
	if s.Name() != "weibo" {
		t.Fatalf("Name() = %q, want %q", s.Name(), "weibo")
	}
}

func TestEndpoints(t *testing.T) {
	s := New("id", "secret", "https://app.example/callback", nil)
	if s.AuthURL() != "https://api.weibo.com/oauth2/authorize" {
		t.Errorf("AuthURL() = %q, want %q", s.AuthURL(), "https://api.weibo.com/oauth2/authorize")
	}
	if s.TokenURL() != "https://api.weibo.com/oauth2/access_token" {
		t.Errorf("TokenURL() = %q, want %q", s.TokenURL(), "https://api.weibo.com/oauth2/access_token")
	}
}
