package mailru

import "testing"

func TestName(t *testing.T) {
	s := New("id", "secret", "https://app.example/callback", nil)
	if s.Name() != "mailru" {
		t.Fatalf("Name() = %q, want %q", s.Name(), "mailru")
	}
}

func TestEndpoints(t *testing.T) {
	s := New("id", "secret", "https://app.example/callback", nil)
	if s.AuthURL() != "https://oauth.mail.ru/login" {
		t.Errorf("AuthURL() = %q, want %q", s.AuthURL(), "https://oauth.mail.ru/login")
	}
	if s.TokenURL() != "https://oauth.mail.ru/token" {
		t.Errorf("TokenURL() = %q, want %q", s.TokenURL(), "https://oauth.mail.ru/token")
	}
}
