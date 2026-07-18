package surveymonkey

import "testing"

func TestName(t *testing.T) {
	s := New("id", "secret", "https://app.example/callback", nil)
	if s.Name() != "surveymonkey" {
		t.Fatalf("Name() = %q, want %q", s.Name(), "surveymonkey")
	}
}

func TestEndpoints(t *testing.T) {
	s := New("id", "secret", "https://app.example/callback", nil)
	if s.AuthURL() != "https://api.surveymonkey.com/oauth/authorize" {
		t.Errorf("AuthURL() = %q, want %q", s.AuthURL(), "https://api.surveymonkey.com/oauth/authorize")
	}
	if s.TokenURL() != "https://api.surveymonkey.com/oauth/token" {
		t.Errorf("TokenURL() = %q, want %q", s.TokenURL(), "https://api.surveymonkey.com/oauth/token")
	}
}
