package gitee

import "testing"

func TestName(t *testing.T) {
	s := New("id", "secret", "https://app.example/callback", nil)
	if s.Name() != "gitee" {
		t.Fatalf("Name() = %q, want %q", s.Name(), "gitee")
	}
}

func TestEndpoints(t *testing.T) {
	s := New("id", "secret", "https://app.example/callback", nil)
	if s.AuthURL() != "https://gitee.com/oauth/authorize" {
		t.Errorf("AuthURL() = %q, want %q", s.AuthURL(), "https://gitee.com/oauth/authorize")
	}
	if s.TokenURL() != "https://gitee.com/oauth/token" {
		t.Errorf("TokenURL() = %q, want %q", s.TokenURL(), "https://gitee.com/oauth/token")
	}
}
