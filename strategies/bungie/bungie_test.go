package bungie

import "testing"

func TestName(t *testing.T) {
	s := New("id", "secret", "https://app.example/callback", nil)
	if s.Name() != "bungie" {
		t.Fatalf("Name() = %q, want %q", s.Name(), "bungie")
	}
}

func TestEndpoints(t *testing.T) {
	s := New("id", "secret", "https://app.example/callback", nil)
	if s.AuthURL() != "https://www.bungie.net/en/OAuth/Authorize" {
		t.Errorf("AuthURL() = %q, want %q", s.AuthURL(), "https://www.bungie.net/en/OAuth/Authorize")
	}
	if s.TokenURL() != "https://www.bungie.net/Platform/App/OAuth/Token/" {
		t.Errorf("TokenURL() = %q, want %q", s.TokenURL(), "https://www.bungie.net/Platform/App/OAuth/Token/")
	}
}
