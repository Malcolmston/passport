package adobe

import "testing"

func TestName(t *testing.T) {
	s := New("id", "secret", "https://app.example/callback", nil)
	if s.Name() != "adobe" {
		t.Fatalf("Name() = %q, want %q", s.Name(), "adobe")
	}
}

func TestEndpoints(t *testing.T) {
	s := New("id", "secret", "https://app.example/callback", nil)
	if s.AuthURL() != "https://ims-na1.adobelogin.com/ims/authorize/v2" {
		t.Errorf("AuthURL() = %q, want %q", s.AuthURL(), "https://ims-na1.adobelogin.com/ims/authorize/v2")
	}
	if s.TokenURL() != "https://ims-na1.adobelogin.com/ims/token/v3" {
		t.Errorf("TokenURL() = %q, want %q", s.TokenURL(), "https://ims-na1.adobelogin.com/ims/token/v3")
	}
}
