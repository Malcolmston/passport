package intuit

import "testing"

func TestName(t *testing.T) {
	s := New("id", "secret", "https://app.example/callback", nil)
	if s.Name() != "intuit" {
		t.Fatalf("Name() = %q, want %q", s.Name(), "intuit")
	}
}

func TestEndpoints(t *testing.T) {
	s := New("id", "secret", "https://app.example/callback", nil)
	if s.AuthURL() != "https://appcenter.intuit.com/connect/oauth2" {
		t.Errorf("AuthURL() = %q, want %q", s.AuthURL(), "https://appcenter.intuit.com/connect/oauth2")
	}
	if s.TokenURL() != "https://oauth.platform.intuit.com/oauth2/v1/tokens/bearer" {
		t.Errorf("TokenURL() = %q, want %q", s.TokenURL(), "https://oauth.platform.intuit.com/oauth2/v1/tokens/bearer")
	}
}
