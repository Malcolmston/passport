package tiktok

import "testing"

func TestName(t *testing.T) {
	s := New("id", "secret", "https://app.example/callback", nil)
	if s.Name() != "tiktok" {
		t.Fatalf("Name() = %q, want %q", s.Name(), "tiktok")
	}
}

func TestEndpoints(t *testing.T) {
	s := New("id", "secret", "https://app.example/callback", nil)
	if s.AuthURL() != "https://www.tiktok.com/v2/auth/authorize/" {
		t.Errorf("AuthURL() = %q, want %q", s.AuthURL(), "https://www.tiktok.com/v2/auth/authorize/")
	}
	if s.TokenURL() != "https://open.tiktokapis.com/v2/oauth/token/" {
		t.Errorf("TokenURL() = %q, want %q", s.TokenURL(), "https://open.tiktokapis.com/v2/oauth/token/")
	}
}
