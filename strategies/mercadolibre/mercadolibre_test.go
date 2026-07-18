package mercadolibre

import "testing"

func TestName(t *testing.T) {
	s := New("id", "secret", "https://app.example/callback", nil)
	if s.Name() != "mercadolibre" {
		t.Fatalf("Name() = %q, want %q", s.Name(), "mercadolibre")
	}
}

func TestEndpoints(t *testing.T) {
	s := New("id", "secret", "https://app.example/callback", nil)
	if s.AuthURL() != "https://auth.mercadolibre.com/authorization" {
		t.Errorf("AuthURL() = %q, want %q", s.AuthURL(), "https://auth.mercadolibre.com/authorization")
	}
	if s.TokenURL() != "https://api.mercadolibre.com/oauth/token" {
		t.Errorf("TokenURL() = %q, want %q", s.TokenURL(), "https://api.mercadolibre.com/oauth/token")
	}
}
