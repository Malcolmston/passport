package arcgis

import "testing"

func TestName(t *testing.T) {
	s := New("id", "secret", "https://app.example/callback", nil)
	if s.Name() != "arcgis" {
		t.Fatalf("Name() = %q, want %q", s.Name(), "arcgis")
	}
}

func TestEndpoints(t *testing.T) {
	s := New("id", "secret", "https://app.example/callback", nil)
	if s.AuthURL() != "https://www.arcgis.com/sharing/rest/oauth2/authorize" {
		t.Errorf("AuthURL() = %q, want %q", s.AuthURL(), "https://www.arcgis.com/sharing/rest/oauth2/authorize")
	}
	if s.TokenURL() != "https://www.arcgis.com/sharing/rest/oauth2/token" {
		t.Errorf("TokenURL() = %q, want %q", s.TokenURL(), "https://www.arcgis.com/sharing/rest/oauth2/token")
	}
}
